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


def test_unparseable_code_is_silent():
    # Partial / non-Python snippets fall through to string rules, not a block.
    assert CodeActionValidator().analyze("def f(:") == []
    assert CodeActionValidator().analyze("this is not python <<<") == []


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
