from __future__ import annotations

import pytest

from acgs_lite import Constitution, Rule, Severity
from acgs_lite.constrained_decoding import InMemoryConstraintEngine, LLGuidanceEngine


def test_in_memory_constraint_engine_records_calls() -> None:
    engine = InMemoryConstraintEngine(mask=[True, False, True], complete=True)

    engine.start()
    mask = engine.compute_mask([1, 2, 3])
    complete = engine.is_complete([1, 2, 3])

    assert engine.started is True
    assert mask == [True, False, True]
    assert complete is True
    assert engine.save_calls == [
        {"method": "start"},
        {"method": "compute_mask", "token_ids": [1, 2, 3]},
        {"method": "is_complete", "token_ids": [1, 2, 3]},
    ]


def test_llguidance_engine_from_json_schema_preserves_schema() -> None:
    schema = {"type": "string", "pattern": "^ok$"}

    engine = LLGuidanceEngine.from_json_schema(schema)

    assert engine.schema == schema
    assert engine.source == "json_schema"


def test_llguidance_engine_from_regex_builds_string_schema() -> None:
    engine = LLGuidanceEngine.from_regex(r"^[A-Z]{2}$")

    assert engine.schema["type"] == "string"
    assert engine.schema["pattern"] == r"^[A-Z]{2}$"
    assert engine.source == "regex"


def test_llguidance_engine_from_constitution_uses_response_schema() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="STATE",
                text="State must be approved or rejected.",
                severity=Severity.HIGH,
                keywords=["approved", "rejected"],
            )
        ]
    )

    engine = LLGuidanceEngine.from_constitution(constitution)

    assert engine.schema == constitution.to_response_schema()
    assert engine.source == "constitution"


def test_llguidance_engine_raises_when_dependency_is_missing() -> None:
    engine = LLGuidanceEngine.from_json_schema({"type": "string"})

    with pytest.raises(RuntimeError, match="llguidance"):
        engine.start()
