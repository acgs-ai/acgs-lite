"""Tests for the AST-based code-action validator (engine/code_analysis.py)."""

from __future__ import annotations

import pytest

from acgs_lite.constitution import Severity
from acgs_lite.engine.code_analysis import CodeActionValidator

pytestmark = pytest.mark.unit


def _ids(violations) -> set[str]:
    return {v.rule_id for v in violations}


def test_clean_code_has_no_findings():
    code = "a = 1\nb = a + 2\nresult = sum([a, b])"
    assert CodeActionValidator().analyze(code) == []


def test_unparseable_code_blocks_fail_closed():
    # H3: code we cannot parse cannot be proven safe, so it is blocked
    # (fail-closed) rather than silently allowed to run.
    findings = CodeActionValidator().analyze("def f(:")
    assert "CODE-UNPARSEABLE" in _ids(findings)
    assert any(v.severity.blocks() for v in findings)


def test_unparseable_code_silent_when_block_disabled():
    # Opt-out restores legacy best-effort behaviour (only safe behind a sandbox).
    v = CodeActionValidator(block_unparseable=False)
    assert v.analyze("def f(:") == []
    assert v.analyze("this is not python <<<") == []


def test_empty_code_returns_empty():
    assert CodeActionValidator().analyze("") == []


def test_critical_import_flagged():
    findings = CodeActionValidator().analyze("import os")
    assert "CODE-IMPORT-CRITICAL" in _ids(findings)
    assert all(v.severity is Severity.CRITICAL for v in findings)
    assert findings[0].severity.blocks()


def test_from_import_of_critical_module_flagged():
    findings = CodeActionValidator().analyze("from subprocess import run")
    assert "CODE-IMPORT-CRITICAL" in _ids(findings)


def test_unauthorized_import_is_high():
    findings = CodeActionValidator().analyze("import requests")
    assert "CODE-IMPORT-FORBIDDEN" in _ids(findings)
    forbidden = next(v for v in findings if v.rule_id == "CODE-IMPORT-FORBIDDEN")
    assert forbidden.severity is Severity.HIGH


def test_authorized_import_allowed():
    assert CodeActionValidator().analyze("import math\nimport json") == []


def test_private_submodule_access_flagged():
    findings = CodeActionValidator().analyze("import random._os")
    assert "CODE-IMPORT-PRIVATE" in _ids(findings)


def test_eval_and_exec_are_critical():
    for snippet in ("eval('1+1')", "exec('x=1')", "compile('1', '<s>', 'eval')"):
        findings = CodeActionValidator().analyze(snippet)
        assert "CODE-EXEC" in _ids(findings), snippet
        assert any(v.severity is Severity.CRITICAL for v in findings)


def test_dangerous_dotted_call_flagged():
    findings = CodeActionValidator().analyze("import os\nos.system('rm -rf /')")
    ids = _ids(findings)
    assert "CODE-IMPORT-CRITICAL" in ids
    assert "CODE-DANGEROUS-CALL" in ids


def test_open_is_high_builtin():
    findings = CodeActionValidator().analyze("open('/etc/passwd')")
    assert "CODE-DANGEROUS-BUILTIN" in _ids(findings)


def test_dunder_escape_attribute_flagged():
    code = "().__class__.__bases__[0].__subclasses__()"
    findings = CodeActionValidator().analyze(code)
    assert "CODE-DUNDER-ACCESS" in _ids(findings)
    assert any(v.severity is Severity.HIGH for v in findings)


def test_introspection_builtins_are_medium_and_optional():
    code = "getattr(obj, 'x')"
    findings = CodeActionValidator().analyze(code)
    assert "CODE-INTROSPECTION" in _ids(findings)
    assert all(v.severity is Severity.MEDIUM for v in findings)
    # Can be disabled.
    assert CodeActionValidator(flag_medium_builtins=False).analyze(code) == []


def test_extra_authorized_imports_whitelists_module():
    code = "import requests"
    assert "CODE-IMPORT-FORBIDDEN" in _ids(CodeActionValidator().analyze(code))
    v = CodeActionValidator(extra_authorized_imports=["requests"])
    assert v.analyze(code) == []


def test_findings_are_deduplicated():
    code = "import os\nimport os"
    findings = CodeActionValidator().analyze(code)
    assert len([v for v in findings if v.rule_id == "CODE-IMPORT-CRITICAL"]) == 1


def test_as_engine_validator_only_runs_on_code_context():
    validator = CodeActionValidator().as_engine_validator()
    # Without the trigger, no analysis happens (treated as plain text).
    assert validator("import os", {}) == []
    assert validator("import os", {"action_type": "text"}) == []
    # With the trigger, structural analysis runs.
    findings = validator("import os", {"action_type": "code"})
    assert "CODE-IMPORT-CRITICAL" in _ids(findings)


def test_as_engine_validator_custom_trigger():
    validator = CodeActionValidator().as_engine_validator(
        trigger_key="lang", trigger_value="python"
    )
    assert validator("import os", {"lang": "python"})
    assert validator("import os", {"lang": "ruby"}) == []


def test_as_engine_validator_is_exception_safe():
    # T3: a parse failure inside the engine custom-validator closure must not
    # raise — it returns a blocking finding (fail-closed), never an exception.
    validator = CodeActionValidator().as_engine_validator()
    out = validator("def f(:", {"action_type": "code"})
    assert "CODE-UNPARSEABLE" in _ids(out)


# -- Fail-closed analysis (H2, L4, L5) -------------------------------------


def test_deep_nesting_cannot_smuggle_dangerous_code():
    # H2: deeply nested input must never analyze to an empty (allow) result,
    # whether the parser overflows (CODE-ANALYSIS-ERROR) or succeeds and the
    # hidden os.system is seen (CODE-DANGEROUS-CALL). Either way: blocked.
    payload = "(" * 2000 + "os.system('id')" + ")" * 2000
    findings = CodeActionValidator().analyze(payload)
    assert findings, "deeply nested input must not analyze to an allow result"
    assert any(v.severity.blocks() for v in findings)


def test_extreme_unary_nesting_fails_closed():
    # Adversarial H2 (MemoryError band): at extreme depth CPython's ast.parse
    # raises MemoryError, not RecursionError — which previously escaped analyze()
    # and let the smuggled call run. Both bands must fail closed (or, if the
    # parse succeeds, the dangerous __import__ is flagged). Either way: blocked.
    payload = "not " * 9000 + "__import__('os').system('id')"
    findings = CodeActionValidator().analyze(payload)
    assert findings, "extreme nesting must not analyze to an allow result"
    assert any(v.severity.blocks() for v in findings)


def test_oversized_code_blocks():
    # L4: refuse to parse pathologically large input.
    big = "a = 1\n" * 50_000
    findings = CodeActionValidator(max_code_size=1000).analyze(big)
    assert "CODE-TOO-LARGE" in _ids(findings)


def test_non_string_input_does_not_raise():
    # L5: the engine custom-validator path must not get a TypeError.
    v = CodeActionValidator()
    assert "CODE-UNANALYZABLE" in _ids(v.analyze(123))  # type: ignore[arg-type]
    assert "CODE-UNANALYZABLE" in _ids(v.analyze(["import os"]))  # type: ignore[arg-type]


def test_bytes_input_is_decoded_and_analyzed():
    findings = CodeActionValidator().analyze(b"import os")  # type: ignore[arg-type]
    assert "CODE-IMPORT-CRITICAL" in _ids(findings)


# -- from-import members (M2) ----------------------------------------------


def test_from_import_dangerous_member_flagged():
    assert "CODE-EXEC" in _ids(CodeActionValidator().analyze("from builtins import __import__"))
    # authorized module, but a dunder member is still an escape vector
    assert "CODE-DUNDER-ACCESS" in _ids(
        CodeActionValidator().analyze("from typing import __globals__")
    )


def test_from_import_private_member_flagged():
    findings = CodeActionValidator().analyze("from json import _default_encoder")
    assert "CODE-IMPORT-PRIVATE" in _ids(findings)


# -- relative imports (M3) -------------------------------------------------


def test_relative_import_not_matched_against_absolute_allowlist():
    # ``from .os import x`` addresses the local package, not stdlib os.
    assert CodeActionValidator().analyze("from .os import helper") == []
    assert CodeActionValidator().analyze("from .utils import thing") == []


# -- getattr string-literal dunder (L2) ------------------------------------


def test_getattr_string_dunder_is_high():
    findings = CodeActionValidator().analyze("getattr(o, '__globals__')")
    assert "CODE-DUNDER-ACCESS" in _ids(findings)
    assert any(v.severity is Severity.HIGH for v in findings)


# -- aliased dangerous call (L3) -------------------------------------------


def test_aliased_dangerous_call_flagged():
    findings = CodeActionValidator().analyze("import os as o\no.system('id')")
    assert "CODE-DANGEROUS-CALL" in _ids(findings)


# -- private C-accelerator modules (L12) -----------------------------------


def test_private_c_accelerator_module_is_critical():
    findings = CodeActionValidator().analyze("import _socket")
    ids = _ids(findings)
    assert "CODE-IMPORT-CRITICAL" in ids
    assert "CODE-IMPORT-PRIVATE" in ids


# -- builtin aliasing (adversarial) ----------------------------------------


def test_aliased_exec_builtin_is_flagged():
    # e = eval; e(...) must not launder a dynamic-execution builtin past the gate.
    assert "CODE-EXEC" in _ids(CodeActionValidator().analyze("e = eval\ne('1+1')"))
    assert "CODE-EXEC" in _ids(CodeActionValidator().analyze("f = __import__\nf('os')"))


def test_exec_builtin_passed_as_argument_is_flagged():
    # Referencing eval at all (e.g. passing it to map) is flagged — there is no
    # legitimate bare reference to eval/exec in sandboxed agent code.
    assert "CODE-EXEC" in _ids(CodeActionValidator().analyze("list(map(eval, ['1']))"))


def test_aliased_high_builtin_call_is_flagged():
    # rd = open; rd(path) resolves through the builtin-alias map to open().
    assert "CODE-DANGEROUS-BUILTIN" in _ids(
        CodeActionValidator().analyze("rd = open\nrd('/etc/passwd')")
    )


def test_aliased_getattr_dunder_is_high():
    # ga = getattr; ga(o, '__subclasses__') is an escape vector via an alias.
    findings = CodeActionValidator().analyze("ga = getattr\nga(object(), '__subclasses__')")
    assert "CODE-DUNDER-ACCESS" in _ids(findings)
    assert any(v.severity is Severity.HIGH for v in findings)


def test_keyword_argument_dunder_is_high():
    # Adversarial (verify-governance-fixes / L2-L3): a dunder smuggled through a
    # KEYWORD argument must still promote to HIGH CODE-DUNDER-ACCESS. Scanning
    # only positional args let setattr(o, name='__dict__', ...) fall through to
    # MEDIUM CODE-INTROSPECTION and slip past the executor gate.
    for code in (
        "setattr(o, name='__dict__', value=1)",
        "setattr(o, '__class__', value=type)",
        "delattr(o, name='__weakref__')",
    ):
        findings = CodeActionValidator().analyze(code)
        ids = _ids(findings)
        assert "CODE-DUNDER-ACCESS" in ids, f"{code!r} -> {ids}"
        assert any(v.severity is Severity.HIGH for v in findings), code


def test_direct_exec_call_not_double_flagged():
    # A plain eval('1') yields exactly one CODE-EXEC (from the call), not also a
    # duplicate bare-name finding.
    exec_findings = [
        v for v in CodeActionValidator().analyze("eval('1')") if v.rule_id == "CODE-EXEC"
    ]
    assert len(exec_findings) == 1


# -- HIGH/MEDIUM builtin laundering: walrus / unpack / annassign / params (#2/#5/#6) --


@pytest.mark.parametrize(
    "code",
    [
        "(rd := open)('/etc/passwd')",  # walrus, immediate call
        "rd = (open)\nrd('/etc/passwd')",  # parenthesised assign
        "a, rd = 1, open\nrd('/etc/passwd')",  # tuple unpack
        "[a, rd] = [1, open]\nrd('/etc/passwd')",  # list unpack
        "rd: object = open\nrd('/etc/passwd')",  # annotated assign
        "a = open\nrd = a\nrd('/etc/passwd')",  # 2-hop alias
        "a = open\nb = a\nc = b\nc('/etc/passwd')",  # 3-hop alias
        "def f(g=open):\n    return g('/etc/passwd')",  # positional param default
        "def f(*, g=open):\n    return g('/etc/passwd')",  # keyword-only param default
        "h = lambda g=open: g('/etc/passwd')",  # lambda param default
    ],
)
def test_high_builtin_laundering_is_flagged(code):
    # A HIGH builtin (open) reaching a call site through any binding form or an
    # alias chain must still resolve to CODE-DANGEROUS-BUILTIN, not slip past the
    # gate. (CRITICAL builtins are also caught as bare references by _check_name.)
    findings = CodeActionValidator().analyze(code)
    assert "CODE-DANGEROUS-BUILTIN" in _ids(findings), f"{code!r} -> {_ids(findings)}"
    assert any(v.severity is Severity.HIGH for v in findings), code


def test_laundering_no_false_positive_on_clean_code():
    # Benign assignments / defaults that never bind a dangerous builtin must not
    # be flagged.
    for code in (
        "x = 1\ny = x\nz = y + 1\nprint(z)",
        "def greet(name='world'):\n    return 'hi ' + name",
        "a, b = 1, 2\nc = a + b",
    ):
        assert CodeActionValidator().analyze(code) == [], code


# -- __builtins__ namespace sandbox escape (#3) ----------------------------


@pytest.mark.parametrize(
    "code",
    [
        "__builtins__['eval']('1+1')",  # subscript into the namespace
        "__builtins__.eval('1+1')",  # attribute on the namespace
        "__builtins__.__import__('os').system('id')",  # __import__ via namespace
        "b = __builtins__\nb['exec']('x=1')",  # aliased namespace
    ],
)
def test_builtins_namespace_reference_is_flagged(code):
    # Referencing the __builtins__ namespace is a sandbox escape that reaches
    # eval/exec/__import__ without the bare name appearing; it must be flagged.
    findings = CodeActionValidator().analyze(code)
    assert "CODE-DUNDER-ACCESS" in _ids(findings), f"{code!r} -> {_ids(findings)}"
    assert any(v.severity.blocks() for v in findings), code


# -- deny lists extend, never shrink, the security floor (#19) -------------


def test_custom_critical_imports_extend_defaults():
    # Passing critical_imports must ADD to the built-in critical set, never drop
    # os/subprocess/… from it (a silent security-floor shrink).
    v = CodeActionValidator(critical_imports=["mycorp_secrets"])
    assert "CODE-IMPORT-CRITICAL" in _ids(v.analyze("import os"))  # default still denied
    assert "CODE-IMPORT-CRITICAL" in _ids(v.analyze("import mycorp_secrets"))  # added


def test_custom_dangerous_calls_extend_defaults():
    v = CodeActionValidator(dangerous_calls=["mymod.wipe"])
    assert "CODE-DANGEROUS-CALL" in _ids(v.analyze("import os\nos.system('x')"))  # default kept
    assert "CODE-DANGEROUS-CALL" in _ids(v.analyze("import mymod\nmymod.wipe()"))  # added
