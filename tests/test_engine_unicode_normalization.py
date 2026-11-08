"""Regression: rule keywords must match Unicode-obfuscated actions.

Matching ran on ``action.lower()`` only, so a fullwidth keyword (``ｄｅｌｅｔｅ``) or a
keyword with a zero-width / soft-hyphen character spliced in (``del​ete``)
evaded a rule blocking ``delete``. The engine now also matches the NFKC-folded,
format-character-stripped text and unions the findings, while every recorded
field keeps the original action string.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from acgs_lite import GovernedCallable
from acgs_lite.audit import AuditLog
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine import GovernanceEngine
from acgs_lite.engine.core import normalize_for_matching
from acgs_lite.engine.matcher import _HAS_AHO, _HAS_RUST
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary

ZWSP = "​"
ZWJ = "‍"
SHY = "­"  # soft hyphen, category Cf

OBFUSCATED_DELETE = [
    pytest.param("please ｄｅｌｅｔｅ the records", id="fullwidth"),
    pytest.param("please ＤＥＬＥＴＥ the records", id="fullwidth-upper"),
    pytest.param(f"please del{ZWSP}ete the records", id="zwsp"),
    pytest.param(f"please de{ZWJ}le{ZWJ}te the records", id="zwj"),
    pytest.param(f"please dele{SHY}te the records", id="soft-hyphen"),
    pytest.param(f"please ｄｅ{ZWSP}ｌｅ{SHY}ｔｅ the records", id="mixed"),
]

# Default_Ignorable_Code_Point values outside category Cf, which NFKC keeps.
INVISIBLE_NON_CF = [
    pytest.param(0x034F, id="U+034F-combining-grapheme-joiner-Mn"),
    pytest.param(0xFE00, id="U+FE00-variation-selector-1-Mn"),
    pytest.param(0xFE0F, id="U+FE0F-variation-selector-16-Mn"),
    pytest.param(0xE0100, id="U+E0100-variation-selector-17-Mn"),
    pytest.param(0xE01EF, id="U+E01EF-variation-selector-256-Mn"),
    pytest.param(0x17B4, id="U+17B4-khmer-inherent-aq-Mn"),
    pytest.param(0x17B5, id="U+17B5-khmer-inherent-aa-Mn"),
    pytest.param(0x115F, id="U+115F-hangul-choseong-filler-Lo"),
    pytest.param(0x1160, id="U+1160-hangul-jungseong-filler-Lo"),
    pytest.param(0x3164, id="U+3164-hangul-filler-Lo"),
    pytest.param(0xFFA0, id="U+FFA0-halfwidth-hangul-filler-Lo"),
    pytest.param(0x2065, id="U+2065-reserved-Cn"),
    pytest.param(0xFFF0, id="U+FFF0-reserved-Cn"),
    pytest.param(0xE0FFF, id="U+E0FFF-reserved-Cn"),
]


def _rules() -> list[Rule]:
    return [
        Rule(
            id="NO-DELETE",
            text="Do not delete records",
            severity=Severity.CRITICAL,
            keywords=["delete"],
        ),
        Rule(
            id="NO-EXFIL",
            text="Do not exfiltrate data",
            severity=Severity.HIGH,
            keywords=["exfiltrate"],
        ),
        Rule(
            id="NO-SSN",
            text="No social security numbers",
            severity=Severity.HIGH,
            patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
        ),
    ]


def _constitution(*, runtime_filtered: bool = False) -> Constitution:
    rules = _rules()
    if runtime_filtered:
        # A deprecated rule routes validate() through the runtime-rule-filtering path.
        rules.append(Rule(id="OLD", text="Retired rule", keywords=["zzretired"], deprecated=True))
    return Constitution.from_rules(rules, name="unicode")


_BACKENDS = ["python-regex"]
if _HAS_AHO:
    _BACKENDS.append("python-ac")
if _HAS_RUST:
    _BACKENDS.append("rust")


@pytest.fixture(params=_BACKENDS)
def backend(request: pytest.FixtureRequest) -> Iterator[str]:
    """Build engines under each available matcher backend.

    ``python-regex`` forces the pure-Python fallback (no Rust, no Aho-Corasick);
    the others run only when the optional extension is importable.
    """
    name: str = request.param
    rust_off = name != "rust"
    aho_off = name == "python-regex"
    with (
        patch("acgs_lite.engine.core._HAS_RUST", not rust_off and _HAS_RUST),
        patch("acgs_lite.engine.core._HAS_AHO", not aho_off and _HAS_AHO),
    ):
        yield name


def _engine(
    *, strict: bool, runtime_filtered: bool = False, audit_log: AuditLog | None = None
) -> GovernanceEngine:
    return GovernanceEngine(
        _constitution(runtime_filtered=runtime_filtered), strict=strict, audit_log=audit_log
    )


class TestNormalizeForMatching:
    def test_ascii_returned_unchanged(self) -> None:
        text = "Delete THE records"
        assert normalize_for_matching(text) is text

    def test_fullwidth_folded(self) -> None:
        assert normalize_for_matching("ｄｅｌｅｔｅ ＤＢ") == "delete DB"

    def test_format_chars_dropped(self) -> None:
        assert normalize_for_matching(f"de{ZWSP}l{ZWJ}e{SHY}te⁠") == "delete"

    def test_benign_text_kept(self) -> None:
        assert normalize_for_matching("café 你好") == "café 你好"

    @pytest.mark.parametrize("code_point", INVISIBLE_NON_CF)
    def test_default_ignorable_non_cf_dropped(self, code_point: int) -> None:
        assert normalize_for_matching(f"de{chr(code_point)}lete") == "delete"

    def test_ascii_hidden_controls_dropped_whitespace_kept(self) -> None:
        assert normalize_for_matching("de\x00l\x01e\x1bt\x7fe") == "delete"
        assert normalize_for_matching("a\tb\nc\rd") == "a\tb\nc\rd"
        assert normalize_for_matching("dé\x00lete") == "délete"

    def test_combining_marks_outside_default_ignorable_kept(self) -> None:
        # U+0332 COMBINING LOW LINE (Mn) has no precomposed form and is not ignorable.
        assert normalize_for_matching("x\u0332y") == "x\u0332y"


@pytest.mark.constitutional
class TestEngineValidate:
    @pytest.mark.parametrize("action", OBFUSCATED_DELETE)
    def test_obfuscated_keyword_denied_non_strict(self, backend: str, action: str) -> None:
        result = _engine(strict=False).validate(action)
        assert result.valid is False
        assert [v.rule_id for v in result.violations] == ["NO-DELETE"]
        assert result.violations[0].matched_content == action

    @pytest.mark.parametrize("action", OBFUSCATED_DELETE)
    def test_obfuscated_keyword_raises_strict(self, backend: str, action: str) -> None:
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            _engine(strict=True).validate(action)
        assert exc_info.value.rule_id == "NO-DELETE"

    @pytest.mark.parametrize("action", OBFUSCATED_DELETE)
    def test_obfuscated_keyword_denied_runtime_filtered(self, backend: str, action: str) -> None:
        result = _engine(strict=False, runtime_filtered=True).validate(action)
        assert [v.rule_id for v in result.violations] == ["NO-DELETE"]

    @pytest.mark.parametrize("code_point", INVISIBLE_NON_CF)
    @pytest.mark.parametrize("runtime_filtered", [False, True])
    def test_default_ignorable_spliced_keyword_denied(
        self, backend: str, code_point: int, runtime_filtered: bool
    ) -> None:
        action = f"please del{chr(code_point)}ete the records"
        result = _engine(strict=False, runtime_filtered=runtime_filtered).validate(action)
        assert result.valid is False
        assert [v.rule_id for v in result.violations] == ["NO-DELETE"]
        assert result.violations[0].matched_content == action
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            _engine(strict=True, runtime_filtered=runtime_filtered).validate(action)
        assert exc_info.value.rule_id == "NO-DELETE"

    @pytest.mark.parametrize(
        "action",
        [
            "great work \u2764\ufe0f thanks",
            "summarise the report \u263a\ufe0f",
            "\u5bb6\u65cf \U0001f44d\ufe0f \u5831\u544a",
        ],
    )
    def test_benign_emoji_presentation_selector_still_valid(
        self, backend: str, action: str
    ) -> None:
        assert "\ufe0f" in action
        assert _engine(strict=True).validate(action).valid is True

    def test_obfuscated_context_value_denied(self, backend: str) -> None:
        detail = "then ｅｘｆｉｌｔｒａｔｅ everything"
        for strict in (False, True):
            engine = _engine(strict=strict)
            if strict:
                with pytest.raises(ConstitutionalViolationError):
                    engine.validate("summarise report", context={"action_detail": detail})
            else:
                result = engine.validate("summarise report", context={"action_detail": detail})
                assert [v.rule_id for v in result.violations] == ["NO-EXFIL"]
                assert result.violations[0].matched_content == f"context[action_detail]: {detail}"

    def test_obfuscated_context_value_denied_runtime_filtered(self, backend: str) -> None:
        detail = f"then exfil{ZWSP}trate everything"
        result = _engine(strict=False, runtime_filtered=True).validate(
            "summarise report", context={"action_description": detail}
        )
        assert [v.rule_id for v in result.violations] == ["NO-EXFIL"]

    def test_normalized_pass_raises_after_original_pass_finds_non_critical(
        self, backend: str
    ) -> None:
        # The original text hits only the HIGH rule; the CRITICAL keyword is visible
        # only after normalization. Strict mode must still raise for the CRITICAL rule.
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            _engine(strict=True).validate("exfiltrate and ｄｅｌｅｔｅ it")
        assert exc_info.value.rule_id in {"NO-DELETE", "NO-EXFIL"}
        result = _engine(strict=False).validate("exfiltrate and ｄｅｌｅｔｅ it")
        assert {v.rule_id for v in result.violations} == {"NO-DELETE", "NO-EXFIL"}

    @pytest.mark.parametrize(
        "action",
        ["please del\x00ete the records", "please de\x01lete the records", "dele\x7fte it"],
    )
    @pytest.mark.parametrize("runtime_filtered", [False, True])
    def test_ascii_control_spliced_keyword_denied(
        self, backend: str, action: str, runtime_filtered: bool
    ) -> None:
        result = _engine(strict=False, runtime_filtered=runtime_filtered).validate(action)
        assert [v.rule_id for v in result.violations] == ["NO-DELETE"]
        assert result.violations[0].matched_content == action
        with pytest.raises(ConstitutionalViolationError):
            _engine(strict=True, runtime_filtered=runtime_filtered).validate(action)

    @pytest.mark.parametrize(
        "action",
        ["send 123-45-6789", "send 123-45-6789 ️", f"send 123-45-6789{ZWSP}"],
    )
    def test_pattern_only_constitution_denies(self, backend: str, action: str) -> None:
        # No keyword rules: no keyword index or anchor, so only the pattern can deny.
        ssn_only = Constitution.from_rules(
            [r for r in _rules() if r.id == "NO-SSN"], name="pattern-only"
        )
        result = GovernanceEngine(ssn_only, strict=False).validate(action)
        assert [v.rule_id for v in result.violations] == ["NO-SSN"]
        with pytest.raises(ConstitutionalViolationError):
            GovernanceEngine(ssn_only, strict=True).validate(action)

    def test_original_and_normalized_hits_are_deduplicated(self, backend: str) -> None:
        result = _engine(strict=False).validate("delete then ｄｅｌｅｔｅ again")
        assert [v.rule_id for v in result.violations] == ["NO-DELETE"]

    def test_fullwidth_digits_hit_pattern_rule(self, backend: str) -> None:
        result = _engine(strict=False).validate("ssn is １２３-４５-６７８９")
        assert [v.rule_id for v in result.violations] == ["NO-SSN"]

    @pytest.mark.parametrize(
        "action",
        ["please delete the records", "summarise the quarterly report", "ssn 123-45-6789"],
    )
    def test_ascii_behaviour_unchanged(self, backend: str, action: str) -> None:
        # Normalization is a no-op on ASCII; compare against the matcher's own verdict.
        result = _engine(strict=False).validate(action)
        expected = {
            "please delete the records": ["NO-DELETE"],
            "summarise the quarterly report": [],
            "ssn 123-45-6789": ["NO-SSN"],
        }[action]
        assert [v.rule_id for v in result.violations] == expected

    @pytest.mark.parametrize(
        "action",
        ["résumé du café", "请总结季度报告", "Ｓｕｍｍａｒｉｓｅ the report", f"sum{ZWSP}marise"],
    )
    def test_benign_non_ascii_still_valid(self, backend: str, action: str) -> None:
        assert _engine(strict=True).validate(action).valid is True

    def test_recorded_action_is_original_full_audit(self, backend: str) -> None:
        audit = AuditLog()
        engine = _engine(strict=False, audit_log=audit)
        action = f"please del{ZWSP}ete the records"
        result = engine.validate(action, agent_id="agent-u")
        assert result.valid is False
        assert result.action == action
        assert [v.matched_content for v in result.violations] == [action]
        entries = audit.entries
        assert len(entries) == 1, "the normalized pass must not write its own audit entry"
        assert entries[0].action == action
        assert entries[0].violations == ["NO-DELETE"]

    def test_recorded_action_is_original_full_audit_strict(self, backend: str) -> None:
        audit = AuditLog()
        engine = _engine(strict=True, audit_log=audit)
        action = "please ｄｅｌｅｔｅ the records"
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            engine.validate(action)
        assert exc_info.value.action == action
        entries = audit.entries
        assert len(entries) == 1
        assert entries[0].action == action
        assert entries[0].valid is False


@pytest.mark.constitutional
class TestGovernedCallableEndToEnd:
    @staticmethod
    def _receipt(method: str) -> DecisionReceipt:
        return DecisionReceipt.create(
            request_id=f"req-{method}",
            goal="Run governed callable test fixture",
            proposed_method=method,
            decision_type="ALLOW",
            authority_basis="test-authority",
            matched_constraints=("test-baseline-rule",),
            policy_version="test-policy-v1",
            execution_boundary=ExecutionBoundary(
                allowed_method=method,
                allowed_scope=None,
                allowed_subjects=(),
                expires_at=None,
                single_use=True,
            ),
        )

    @pytest.mark.parametrize("action", OBFUSCATED_DELETE)
    def test_obfuscated_argument_denied_function_not_run(self, backend: str, action: str) -> None:
        calls: list[str] = []

        @GovernedCallable(_constitution())
        def process(input: str) -> str:
            calls.append(input)
            return "ok"

        with pytest.raises(ConstitutionalViolationError) as exc_info:
            process(action, decision_receipt=self._receipt("process"))
        assert exc_info.value.rule_id == "NO-DELETE"
        assert calls == []

    def test_obfuscated_keyword_argument_denied(self, backend: str) -> None:
        calls: list[str] = []

        @GovernedCallable(_constitution())
        def process(*, input: str) -> str:
            calls.append(input)
            return "ok"

        with pytest.raises(ConstitutionalViolationError):
            process(input=f"exfil{SHY}trate it", decision_receipt=self._receipt("process"))
        assert calls == []

    def test_benign_argument_runs(self, backend: str) -> None:
        @GovernedCallable(_constitution())
        def process(input: str) -> str:
            return f"done: {input}"

        assert process("résumé du café", decision_receipt=self._receipt("process")) == (
            "done: résumé du café"
        )
