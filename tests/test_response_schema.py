from __future__ import annotations

from acgs_lite.constitution import Constitution, Rule, Severity


def test_empty_constitution_response_schema() -> None:
    constitution = Constitution.from_rules([])

    schema = constitution.to_response_schema()

    assert schema["title"] == "custom Response Schema"
    assert schema["properties"] == {}
    assert schema["required"] == []
    assert schema["additionalProperties"] is True  # permissive by default
    assert schema["x-acgs-exported-rule-count"] == 0
    assert schema["x-acgs-skipped-rules"] == []
    assert schema["x-acgs-skipped-rule-count"] == 0


def test_patterns_only_rules_export_pattern_constraints() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="STATUS",
                text="Status must be uppercase letters.",
                severity=Severity.CRITICAL,
                patterns=[r"^[A-Z]{3}$"],
            )
        ]
    )

    schema = constitution.to_response_schema()

    assert schema["required"] == ["STATUS"]
    assert schema["properties"]["STATUS"]["pattern"] == r"^[A-Z]{3}$"
    assert schema["x-acgs-skipped-rules"] == []


def test_keywords_only_rules_export_enum_constraints() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="DECISION",
                text="Decision must be approved or rejected.",
                severity=Severity.MEDIUM,
                keywords=["approved", "rejected"],
            )
        ]
    )

    schema = constitution.to_response_schema()

    assert schema["required"] == []
    assert schema["properties"]["DECISION"]["enum"] == ["approved", "rejected"]


def test_mixed_rules_export_required_and_optional_properties() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="STATE",
                text="State must be approved or rejected.",
                severity=Severity.HIGH,
                keywords=["approved", "rejected"],
                patterns=[r"^(approved|rejected)$"],
            ),
            Rule(
                id="TRACE",
                text="Trace id must be lowercase hex.",
                severity=Severity.LOW,
                patterns=[r"^[a-f0-9]{8}$"],
            ),
        ]
    )

    schema = constitution.to_response_schema()

    assert schema["required"] == ["STATE"]
    assert schema["properties"]["STATE"]["enum"] == ["approved", "rejected"]
    assert schema["properties"]["STATE"]["pattern"] == r"^(approved|rejected)$"
    assert schema["properties"]["TRACE"]["pattern"] == r"^[a-f0-9]{8}$"


def test_semantic_only_rules_are_skipped() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="NO-PII",
                text="Do not expose PII in responses.",
                severity=Severity.CRITICAL,
            )
        ]
    )

    schema = constitution.to_response_schema()

    assert schema["properties"] == {}
    assert schema["required"] == []
    assert schema["x-acgs-exported-rule-count"] == 0
    assert schema["x-acgs-skipped-rules"] == [
        {"id": "NO-PII", "reason": "no_structural_constraints"}
    ]
    assert schema["x-acgs-skipped-rule-count"] == 1


# --- Phase 1: strict parameter ---


def test_strict_false_sets_additional_properties_true() -> None:
    constitution = Constitution.from_rules(
        [Rule(id="R1", text="test", severity=Severity.LOW, keywords=["a"])]
    )

    schema = constitution.to_response_schema(strict=False)

    assert schema["additionalProperties"] is True


def test_strict_true_sets_additional_properties_false() -> None:
    constitution = Constitution.from_rules(
        [Rule(id="R1", text="test", severity=Severity.LOW, keywords=["a"])]
    )

    schema = constitution.to_response_schema(strict=True)

    assert schema["additionalProperties"] is False


# --- Phase 2: skipped rules audit metadata ---


def test_disabled_rules_skipped_with_reason() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="ACTIVE",
                text="Active rule.",
                severity=Severity.HIGH,
                keywords=["ok"],
            ),
            Rule(
                id="OFF",
                text="Disabled rule.",
                severity=Severity.HIGH,
                keywords=["nope"],
                enabled=False,
            ),
        ]
    )

    schema = constitution.to_response_schema()

    assert "ACTIVE" in schema["properties"]
    assert "OFF" not in schema["properties"]
    assert {"id": "OFF", "reason": "disabled"} in schema["x-acgs-skipped-rules"]


def test_deprecated_rules_skipped_with_reason() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(
                id="OLD",
                text="Deprecated rule.",
                severity=Severity.HIGH,
                keywords=["legacy"],
                deprecated=True,
            ),
        ]
    )

    schema = constitution.to_response_schema()

    assert "OLD" not in schema["properties"]
    assert {"id": "OLD", "reason": "deprecated"} in schema["x-acgs-skipped-rules"]


def test_all_skip_reasons_present_in_mixed_constitution() -> None:
    constitution = Constitution.from_rules(
        [
            Rule(id="OK", text="Good rule.", severity=Severity.HIGH, patterns=[r"^\d+$"]),
            Rule(id="OFF", text="Disabled.", severity=Severity.LOW, keywords=["x"], enabled=False),
            Rule(
                id="OLD", text="Deprecated.", severity=Severity.LOW, keywords=["y"], deprecated=True
            ),
            Rule(id="SEMANTIC", text="No patterns or keywords.", severity=Severity.CRITICAL),
        ]
    )

    schema = constitution.to_response_schema()

    assert schema["x-acgs-exported-rule-count"] == 1
    assert schema["x-acgs-skipped-rule-count"] == 3

    skip_ids = {s["id"] for s in schema["x-acgs-skipped-rules"]}
    assert skip_ids == {"OFF", "OLD", "SEMANTIC"}

    skip_map = {s["id"]: s["reason"] for s in schema["x-acgs-skipped-rules"]}
    assert skip_map["OFF"] == "disabled"
    assert skip_map["OLD"] == "deprecated"
    assert skip_map["SEMANTIC"] == "no_structural_constraints"
