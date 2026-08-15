"""AMD GAIA governance seams — fail-closed PolicyEngine and companions."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from acgs_lite import Constitution, Rule, Severity, ViolationAction
from acgs_lite.engine import GovernanceEngine
from acgs_lite.integrations.gaia import (
    AcgsLiteCheckpointRuntime,
    AcgsLitePolicyEngine,
    AcgsLiteReceiptService,
    ReceiptRecord,
    build_gaia_components,
)


@dataclass
class _Action:
    action_id: str = "act_1"
    actor_id: str = "alice"
    tool_name: str = "search"
    action_type: str = "tool_call"
    args: dict[str, Any] = field(default_factory=dict)
    risk_tags: list[str] = field(default_factory=list)
    workflow_id: str | None = "wf_1"
    source: str = "gaia"


def _engine_for(keywords: list[str], *, action: ViolationAction) -> GovernanceEngine:
    return GovernanceEngine(
        Constitution.from_rules(
            [
                Rule(
                    id="GAIA-TEST-1",
                    text=f"Rule for {keywords}",
                    keywords=keywords,
                    severity=Severity.HIGH,
                    workflow_action=action,
                )
            ]
        ),
        strict=True,
    )


def test_allow_when_constitution_is_silent() -> None:
    engine = AcgsLitePolicyEngine(engine=_engine_for(["wipe-disk"], action=ViolationAction.BLOCK))
    decision = engine.evaluate_action(_Action(tool_name="search", args={"q": "weather"}))
    assert decision.decision == "ALLOW"


def test_constitution_blocks_tool_payload() -> None:
    engine = AcgsLitePolicyEngine(engine=_engine_for(["wipe-disk"], action=ViolationAction.BLOCK))
    decision = engine.evaluate_action(_Action(tool_name="shell", args={"cmd": "wipe-disk /"}))
    assert decision.decision == "BLOCK"
    assert "GAIA-TEST-1" in decision.rule_ids


def test_constitution_review_maps_to_gaia_review() -> None:
    engine = AcgsLitePolicyEngine(
        engine=_engine_for(["send-mail"], action=ViolationAction.REQUIRE_HUMAN_REVIEW)
    )
    decision = engine.evaluate_action(
        _Action(tool_name="email", args={"to": "a@b.com", "body": "send-mail"})
    )
    assert decision.decision == "REVIEW"


def test_risk_tag_floor_blocks_even_if_constitution_allows() -> None:
    engine = AcgsLitePolicyEngine(engine=_engine_for(["never-match"], action=ViolationAction.BLOCK))
    decision = engine.evaluate_action(_Action(tool_name="shell", risk_tags=["blocked"]))
    assert decision.decision == "BLOCK"
    assert "gaia:risk-tag:blocked" in decision.rule_ids


def test_risk_tag_cannot_loosen_a_block() -> None:
    engine = AcgsLitePolicyEngine(engine=_engine_for(["wipe-disk"], action=ViolationAction.BLOCK))
    decision = engine.evaluate_action(
        _Action(tool_name="shell", args={"cmd": "wipe-disk"}, risk_tags=["review"])
    )
    assert decision.decision == "BLOCK"


def test_missing_tool_name_fails_closed() -> None:
    engine = AcgsLitePolicyEngine()
    decision = engine.evaluate_action(_Action(tool_name=""))
    assert decision.decision == "BLOCK"
    assert "acgs:malformed-request" in decision.rule_ids


def test_non_mapping_args_fail_closed() -> None:
    engine = AcgsLitePolicyEngine()
    decision = engine.evaluate_action(_Action(args="not-a-dict"))  # type: ignore[arg-type]
    assert decision.decision == "BLOCK"


def test_engine_exception_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = AcgsLitePolicyEngine()

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("matcher exploded")

    monkeypatch.setattr(engine.engine, "validate", _boom)
    decision = engine.evaluate_action(_Action())
    assert decision.decision == "BLOCK"
    assert "acgs:fail-closed" in decision.rule_ids


def test_auto_approve_env_is_not_a_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAIA_AUTO_APPROVE_TOOLS", "1")
    engine = AcgsLitePolicyEngine(engine=_engine_for(["wipe-disk"], action=ViolationAction.BLOCK))
    decision = engine.evaluate_action(_Action(tool_name="shell", args={"cmd": "wipe-disk"}))
    assert decision.decision == "BLOCK"


def test_checkpoint_workflow_binding_and_unknown_id() -> None:
    runtime = AcgsLiteCheckpointRuntime()
    transition = SimpleNamespace(
        workflow_id="wf-a",
        transition_id="tx-1",
        related_action_id="act-1",
    )
    opened = runtime.create_checkpoint(transition, SimpleNamespace(decision="REVIEW", reason="x"))
    assert runtime.get_checkpoint(opened.checkpoint_id).workflow_id == "wf-a"

    missing = runtime.resolve_checkpoint("nope", SimpleNamespace(resolution="APPROVE", reason=""))
    assert missing.status == "TERMINATED"
    assert missing.metadata["fail_closed"] is True

    approved = runtime.resolve_checkpoint(
        opened.checkpoint_id, SimpleNamespace(resolution="APPROVE", reason="ok")
    )
    assert approved.status == "RESUMED"

    reused = runtime.resolve_checkpoint(
        opened.checkpoint_id, SimpleNamespace(resolution="APPROVE", reason="again")
    )
    assert reused.status == "TERMINATED"


def test_unsupported_resolution_fails_closed() -> None:
    runtime = AcgsLiteCheckpointRuntime()
    opened = runtime.create_checkpoint(
        SimpleNamespace(workflow_id="wf-a", transition_id="tx", related_action_id=None),
        SimpleNamespace(decision="REVIEW", reason="x"),
    )
    outcome = runtime.resolve_checkpoint(
        opened.checkpoint_id, SimpleNamespace(resolution="ESCALATE", reason="")
    )
    assert outcome.status == "TERMINATED"


def test_receipt_service_round_trip() -> None:
    service = AcgsLiteReceiptService()
    record = ReceiptRecord(
        receipt_id="rcpt_test",
        workflow_id="wf-a",
        checkpoint_id=None,
        decision="BLOCK",
        policy_version="1.0.0",
        actor_id="alice",
        validator_set_id=None,
        created_at="2026-08-15T00:00:00+00:00",
        payload_hash="abc",
        metadata={"constitution_hash": "hash"},
    )
    issued = service.issue_receipt(record)
    assert issued == "rcpt_test"
    assert service.get_receipt("rcpt_test") is record
    with pytest.raises(KeyError):
        service.get_receipt("missing")


def test_build_gaia_components_bind_constitution_hash() -> None:
    constitution = Constitution.from_rules(
        [Rule(id="R1", text="demo", keywords=["demo"], severity=Severity.LOW)]
    )
    engine, _ck, _rcpt, binding = build_gaia_components(constitution)
    version = binding.current_version()
    assert version.constitution_hash == constitution.hash
    assert engine.evaluate_action(_Action(args={"q": "hello"})).policy_version == version.version
