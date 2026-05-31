"""AST-based static analysis of generated code actions.

This module adapts the security model of HuggingFace ``smolagents``'
``LocalPythonExecutor`` into an ACGS-Lite governance primitive.  Where the
engine's keyword/regex matcher reasons about *strings*, this validator reasons
about the *structure* of Python source — catching things a substring match
cannot: forbidden imports, private-submodule access, sandbox-escape attribute
chains (``__subclasses__``, ``__globals__``, …), and dangerous calls such as
``os.system`` or ``eval``.

It produces plain :class:`~acgs_lite.engine.models.Violation` records, so it
plugs into the existing enforcement/audit pipeline two ways:

1. Directly — call :meth:`CodeActionValidator.analyze` on a code snippet.
2. As a custom validator — register
   :meth:`CodeActionValidator.as_engine_validator` with a
   :class:`~acgs_lite.engine.core.GovernanceEngine` so a single
   ``engine.validate(code, context={"action_type": "code"})`` applies both the
   constitution's string rules and these structural rules under one
   enforcement/audit decision.

The analyzer is deliberately conservative and configurable: it never executes
code, and any module/builtin/attribute set can be overridden at construction.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from typing import Any

from acgs_lite.constitution import Severity
from acgs_lite.engine.models import CustomValidator, Violation

# Modules safe to import inside generated code (mirrors smolagents'
# BASE_BUILTIN_MODULES, trimmed to side-effect-free stdlib).
DEFAULT_AUTHORIZED_IMPORTS: frozenset[str] = frozenset(
    {
        "math",
        "re",
        "datetime",
        "collections",
        "itertools",
        "statistics",
        "queue",
        "time",
        "unicodedata",
        "random",
        "json",
        "string",
        "functools",
        "operator",
        "decimal",
        "fractions",
        "typing",
        "dataclasses",
        "enum",
        "textwrap",
        "heapq",
        "bisect",
    }
)

# Imports that are not merely unauthorized but actively high-risk (filesystem,
# process, network, code-loading, serialization).  Importing any of these is a
# CRITICAL finding regardless of the authorized list.
CRITICAL_IMPORTS: frozenset[str] = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "socket",
        "shutil",
        "ctypes",
        "importlib",
        "multiprocessing",
        "threading",
        "pickle",
        "marshal",
        "pty",
        "fcntl",
        "resource",
        "builtins",
        "code",
        "codeop",
    }
)

# Builtin call targets, tiered by severity.
CRITICAL_BUILTINS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})
HIGH_BUILTINS: frozenset[str] = frozenset({"open", "input", "breakpoint", "exit", "quit"})
MEDIUM_BUILTINS: frozenset[str] = frozenset(
    {"getattr", "setattr", "delattr", "vars", "globals", "locals"}
)

# Dotted call targets that are dangerous wherever they appear.
DANGEROUS_CALLS: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "os.kill",
        "os.fork",
        "os.execv",
        "os.execve",
        "os.execvp",
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "shutil.rmtree",
        "sys.exit",
        "importlib.import_module",
    }
)

# Attribute names used for sandbox escape, tiered by severity.
HIGH_DUNDERS: frozenset[str] = frozenset(
    {
        "__globals__",
        "__builtins__",
        "__subclasses__",
        "__bases__",
        "__base__",
        "__mro__",
        "__code__",
        "__closure__",
        "__loader__",
        "__spec__",
    }
)
MEDIUM_DUNDERS: frozenset[str] = frozenset(
    {"__class__", "__dict__", "__getattribute__", "__reduce__", "__reduce_ex__"}
)


def _dotted_name(node: ast.AST) -> str | None:
    """Return the dotted name for an attribute/name chain, else ``None``.

    ``os.path.join`` → ``"os.path.join"``; a subscript or call in the chain
    yields ``None`` (we cannot statically resolve it to a single target).
    """
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


class CodeActionValidator:
    """Structural validator for Python code produced as an agent action.

    Example::

        validator = CodeActionValidator()
        findings = validator.analyze("import os\\nos.system('rm -rf /')")
        # -> [Violation(rule_id='CODE-IMPORT-CRITICAL', ...),
        #     Violation(rule_id='CODE-DANGEROUS-CALL', ...)]

    Register it with the engine so code is governed under one decision::

        engine.add_validator(validator.as_engine_validator())
        engine.validate(code, context={"action_type": "code"})
    """

    def __init__(
        self,
        *,
        authorized_imports: Iterable[str] | None = None,
        extra_authorized_imports: Iterable[str] | None = None,
        critical_imports: Iterable[str] | None = None,
        dangerous_calls: Iterable[str] | None = None,
        category: str = "code-analysis",
        flag_medium_builtins: bool = True,
    ) -> None:
        base = set(DEFAULT_AUTHORIZED_IMPORTS if authorized_imports is None else authorized_imports)
        if extra_authorized_imports:
            base |= set(extra_authorized_imports)
        self.authorized_imports: frozenset[str] = frozenset(base)
        self.critical_imports: frozenset[str] = frozenset(
            CRITICAL_IMPORTS if critical_imports is None else critical_imports
        )
        self.dangerous_calls: frozenset[str] = frozenset(
            DANGEROUS_CALLS if dangerous_calls is None else dangerous_calls
        )
        self.category = category
        self.flag_medium_builtins = flag_medium_builtins

    def _violation(self, rule_id: str, text: str, severity: Severity, matched: str) -> Violation:
        return Violation(
            rule_id=rule_id,
            rule_text=text,
            severity=severity,
            matched_content=matched[:200],
            category=self.category,
        )

    def analyze(self, code: str) -> list[Violation]:
        """Return structural violations for *code* (empty if clean/unparseable).

        Unparseable input returns ``[]`` rather than a violation: a partial or
        non-Python snippet should fall through to the engine's string rules
        instead of being blocked on a syntax error.
        """
        if not code:
            return []
        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            return []

        raw: list[Violation] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw.extend(self._check_import(alias.name, f"import {alias.name}"))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = ", ".join(a.name for a in node.names)
                raw.extend(self._check_import(module, f"from {module} import {names}"))
            elif isinstance(node, ast.Call):
                raw.extend(self._check_call(node))
            elif isinstance(node, ast.Attribute):
                raw.extend(self._check_attribute(node))

        # Dedup by (rule_id, matched_content), preserving encounter order.
        seen: set[tuple[str, str]] = set()
        findings: list[Violation] = []
        for v in raw:
            key = (v.rule_id, v.matched_content)
            if key not in seen:
                seen.add(key)
                findings.append(v)
        return findings

    def _check_import(self, module: str, matched: str) -> list[Violation]:
        if not module:
            return []
        out: list[Violation] = []
        root = module.split(".")[0]
        if root in self.critical_imports:
            out.append(
                self._violation(
                    "CODE-IMPORT-CRITICAL",
                    f"High-risk import not permitted in generated code: {root}",
                    Severity.CRITICAL,
                    matched,
                )
            )
        elif root not in self.authorized_imports:
            out.append(
                self._violation(
                    "CODE-IMPORT-FORBIDDEN",
                    f"Import not in authorized list: {root}",
                    Severity.HIGH,
                    matched,
                )
            )
        # Private submodule access (e.g. ``random._os``) even of an allowed root.
        if any(part.startswith("_") for part in module.split(".")[1:]):
            out.append(
                self._violation(
                    "CODE-IMPORT-PRIVATE",
                    f"Access to a private submodule is not permitted: {module}",
                    Severity.MEDIUM,
                    matched,
                )
            )
        return out

    def _check_call(self, node: ast.Call) -> list[Violation]:
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if name in CRITICAL_BUILTINS:
                return [
                    self._violation(
                        "CODE-EXEC",
                        f"Dynamic code execution builtin is forbidden: {name}()",
                        Severity.CRITICAL,
                        f"{name}(...)",
                    )
                ]
            if name in HIGH_BUILTINS:
                return [
                    self._violation(
                        "CODE-DANGEROUS-BUILTIN",
                        f"Risky builtin call: {name}()",
                        Severity.HIGH,
                        f"{name}(...)",
                    )
                ]
            if self.flag_medium_builtins and name in MEDIUM_BUILTINS:
                return [
                    self._violation(
                        "CODE-INTROSPECTION",
                        f"Introspection builtin can enable sandbox escape: {name}()",
                        Severity.MEDIUM,
                        f"{name}(...)",
                    )
                ]
            return []
        dotted = _dotted_name(func)
        if dotted is not None and dotted in self.dangerous_calls:
            return [
                self._violation(
                    "CODE-DANGEROUS-CALL",
                    f"Dangerous call is forbidden in generated code: {dotted}()",
                    Severity.CRITICAL,
                    f"{dotted}(...)",
                )
            ]
        return []

    def _check_attribute(self, node: ast.Attribute) -> list[Violation]:
        attr = node.attr
        if attr in HIGH_DUNDERS:
            return [
                self._violation(
                    "CODE-DUNDER-ACCESS",
                    f"Access to escape-vector attribute is forbidden: {attr}",
                    Severity.HIGH,
                    _dotted_name(node) or attr,
                )
            ]
        if attr in MEDIUM_DUNDERS:
            return [
                self._violation(
                    "CODE-DUNDER-ACCESS",
                    f"Access to introspection attribute is restricted: {attr}",
                    Severity.MEDIUM,
                    _dotted_name(node) or attr,
                )
            ]
        return []

    def as_engine_validator(
        self,
        *,
        trigger_key: str = "action_type",
        trigger_value: str = "code",
    ) -> CustomValidator:
        """Return a :data:`CustomValidator` that runs only on code actions.

        The returned callable analyzes the action **only** when
        ``context[trigger_key] == trigger_value`` so that ordinary
        natural-language validations are never parsed as Python.
        """

        def _validator(action: str, context: dict[str, Any]) -> list[Violation]:
            if context.get(trigger_key) != trigger_value:
                return []
            return self.analyze(action)

        return _validator


__all__ = [
    "CRITICAL_BUILTINS",
    "CRITICAL_IMPORTS",
    "DANGEROUS_CALLS",
    "DEFAULT_AUTHORIZED_IMPORTS",
    "HIGH_BUILTINS",
    "HIGH_DUNDERS",
    "MEDIUM_BUILTINS",
    "MEDIUM_DUNDERS",
    "CodeActionValidator",
]
