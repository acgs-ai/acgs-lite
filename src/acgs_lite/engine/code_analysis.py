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

**Fail-closed by default.** For a governance layer guarding code *before it
runs*, "I could not analyze this" must not silently mean "allowed". When the
analyzer cannot parse a snippet, exceeds its size bound, or hits a
``RecursionError`` on pathologically nested input, it emits a *blocking*
violation rather than an empty result.  Set ``block_unparseable=False`` to
restore the old best-effort behaviour (e.g. when stacking the analyzer behind
another sandbox).

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
# CRITICAL finding regardless of the authorized list.  Private C-accelerator
# twins (``_socket``, ``_ctypes`` …) are included so they cannot slip through at
# the lower CODE-IMPORT-FORBIDDEN tier (see L12).
CRITICAL_IMPORTS: frozenset[str] = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "_posixsubprocess",
        "socket",
        "_socket",
        "ssl",
        "_ssl",
        "shutil",
        "ctypes",
        "_ctypes",
        "importlib",
        "multiprocessing",
        "threading",
        "_thread",
        "pickle",
        "_pickle",
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
# Introspection builtins whose first string-literal argument we inspect: a
# dunder target (``getattr(o, "__globals__")``) is an escape vector, not noise.
_ATTR_BUILTINS: frozenset[str] = frozenset({"getattr", "setattr", "delattr"})

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

# Default upper bound on the size of a single code action (characters).  Beyond
# this we refuse to parse rather than spend unbounded time/stack on hostile
# input (see H2/L4).  ``ast.parse`` recurses in CPython, so deeply nested but
# "small" source can still blow the stack — handled separately via RecursionError.
DEFAULT_MAX_CODE_SIZE = 100_000


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

    Parameters
    ----------
    block_unparseable:
        When ``True`` (default), code that cannot be parsed, exceeds
        ``max_code_size``, or overflows the parser stack yields a *blocking*
        violation (fail-closed).  When ``False``, such input yields ``[]``
        (legacy best-effort behaviour — only safe behind another sandbox).
    max_code_size:
        Reject code longer than this many characters before parsing.  ``0``
        disables the bound.
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
        block_unparseable: bool = True,
        max_code_size: int = DEFAULT_MAX_CODE_SIZE,
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
        self.block_unparseable = block_unparseable
        self.max_code_size = max_code_size

    def _violation(self, rule_id: str, text: str, severity: Severity, matched: str) -> Violation:
        return Violation(
            rule_id=rule_id,
            rule_text=text,
            severity=severity,
            matched_content=matched[:200],
            category=self.category,
        )

    def _fail_closed(
        self, rule_id: str, text: str, severity: Severity, matched: str
    ) -> list[Violation]:
        """Return a blocking violation when fail-closed, else nothing.

        Central choke point for every "could not analyze this" outcome so the
        fail-open vs. fail-closed policy lives in exactly one place.
        """
        if not self.block_unparseable:
            return []
        return [self._violation(rule_id, text, severity, matched)]

    def analyze(self, code: str) -> list[Violation]:
        """Return structural violations for *code*.

        Clean, fully-parsed code with no findings returns ``[]``.  Code that
        cannot be analyzed (unparseable, oversized, too deeply nested, or not a
        string) returns a *blocking* violation when ``block_unparseable`` is set
        — never a silent empty list, which would let dangerous code run
        ungoverned (see H2/H3).
        """
        # L5: only ``str`` is analyzable. Decode bytes; refuse other types
        # fail-closed instead of raising TypeError out of the engine path.
        if isinstance(code, bytes):
            try:
                code = code.decode("utf-8")
            except UnicodeDecodeError:
                return self._fail_closed(
                    "CODE-UNPARSEABLE",
                    "Code action is not valid UTF-8; blocked (fail-closed).",
                    Severity.HIGH,
                    "<non-utf8>",
                )
        if not isinstance(code, str):
            return self._fail_closed(
                "CODE-UNANALYZABLE",
                f"Code action is not a string ({type(code).__name__}); blocked (fail-closed).",
                Severity.HIGH,
                repr(code),
            )
        if not code:
            return []
        # L4: bound the work before touching the parser.
        if self.max_code_size and len(code) > self.max_code_size:
            return self._fail_closed(
                "CODE-TOO-LARGE",
                f"Code action exceeds {self.max_code_size} chars ({len(code)}); blocked.",
                Severity.HIGH,
                f"<{len(code)} chars>",
            )

        try:
            tree = ast.parse(code)
        except (SyntaxError, ValueError):
            # Genuinely unparseable: cannot prove it safe, so block (fail-closed).
            return self._fail_closed(
                "CODE-UNPARSEABLE",
                "Code action could not be parsed; blocked (fail-closed).",
                Severity.HIGH,
                "<unparseable>",
            )
        except (RecursionError, MemoryError):
            # H2: deeply nested source overflows the parser. CPython raises
            # RecursionError at moderate depth but MemoryError at extreme depth
            # (e.g. ``"not " * 9000``); both mean "too deep to analyze" → block.
            return self._fail_closed(
                "CODE-ANALYSIS-ERROR",
                "Code action too deeply nested to analyze; blocked (fail-closed).",
                Severity.CRITICAL,
                "<recursion-limit>",
            )
        except Exception:  # noqa: BLE001 - any other parser failure is unanalyzable
            # Fail-closed catch-all: an action we could not prove safe must never
            # fall through to execution because the parser raised a new error type.
            return self._fail_closed(
                "CODE-ANALYSIS-ERROR",
                "Code action could not be analyzed; blocked (fail-closed).",
                Severity.CRITICAL,
                "<analysis-error>",
            )

        try:
            nodes = list(ast.walk(tree))
        except (RecursionError, MemoryError):  # pragma: no cover - ast.walk is iterative; defensive
            return self._fail_closed(
                "CODE-ANALYSIS-ERROR",
                "Code action too complex to analyze; blocked (fail-closed).",
                Severity.CRITICAL,
                "<recursion-limit>",
            )
        except Exception:  # noqa: BLE001 - fail closed on any walk failure
            return self._fail_closed(
                "CODE-ANALYSIS-ERROR",
                "Code action could not be analyzed; blocked (fail-closed).",
                Severity.CRITICAL,
                "<analysis-error>",
            )

        # First pass: resolve import aliases so ``import os as o; o.system(...)``
        # is still caught (L3), and builtin aliases so a dangerous builtin
        # laundered through a local name (``e = eval; e(...)``; ``rd = open;
        # rd(...)``) cannot reach execution unflagged (builtin-aliasing bypass).
        alias_map = self._collect_aliases(nodes)
        builtin_aliases = self._collect_builtin_aliases(nodes)
        # Names that are the direct callee of a call are inspected in
        # ``_check_call``; skip them in the bare-reference scan so a plain
        # ``eval('...')`` is not flagged twice.
        call_func_ids = {id(n.func) for n in nodes if isinstance(n, ast.Call)}

        raw: list[Violation] = []
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    raw.extend(self._check_import(alias.name, 0, f"import {alias.name}"))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                level = node.level or 0
                names = ", ".join(a.name for a in node.names)
                prefix = "." * level
                raw.extend(
                    self._check_import(module, level, f"from {prefix}{module} import {names}")
                )
                # M2: inspect each imported *member* name, not just the module.
                raw.extend(self._check_imported_members(module, level, node.names))
            elif isinstance(node, ast.Call):
                raw.extend(self._check_call(node, alias_map, builtin_aliases))
            elif isinstance(node, ast.Attribute):
                raw.extend(self._check_attribute(node))
            elif isinstance(node, ast.Name):
                raw.extend(self._check_name(node, call_func_ids))

        # Dedup by (rule_id, matched_content), preserving encounter order.
        seen: set[tuple[str, str]] = set()
        findings: list[Violation] = []
        for v in raw:
            key = (v.rule_id, v.matched_content)
            if key not in seen:
                seen.add(key)
                findings.append(v)
        return findings

    @staticmethod
    def _collect_aliases(nodes: list[ast.AST]) -> dict[str, str]:
        """Map local binding → real root module for ``import x as y`` forms.

        ``import os as o`` → ``{"o": "os"}``; ``import os.path as p`` →
        ``{"p": "os"}``.  Used to resolve aliased dangerous calls.
        """
        aliases: dict[str, str] = {}
        for node in nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    aliases[alias.asname or alias.name.split(".")[0]] = root
            elif isinstance(node, ast.ImportFrom) and not node.level:
                module_root = (node.module or "").split(".")[0]
                for alias in node.names:
                    # ``from os import system as s`` → s resolves to ``os.system``.
                    bound = alias.asname or alias.name
                    aliases[bound] = f"{module_root}.{alias.name}" if module_root else alias.name
        return aliases

    @staticmethod
    def _collect_builtin_aliases(nodes: list[ast.AST]) -> dict[str, str]:
        """Map a local name → the dangerous builtin it was assigned from.

        ``e = eval`` → ``{"e": "eval"}``; ``rd = open`` → ``{"rd": "open"}``.
        Used so a builtin laundered through a plain assignment is still resolved
        to its real identity at the call site (builtin-aliasing bypass).
        """
        dangerous = CRITICAL_BUILTINS | HIGH_BUILTINS | MEDIUM_BUILTINS
        aliases: dict[str, str] = {}
        for node in nodes:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Name)
                and node.value.id in dangerous
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = node.value.id
        return aliases

    def _check_name(self, node: ast.Name, call_func_ids: set[int]) -> list[Violation]:
        """Flag a bare *reference* to a dynamic-execution builtin.

        ``e = eval``, ``list(map(eval, …))``, ``[exec]`` — a load of
        ``eval``/``exec``/``compile``/``__import__`` that is not itself the
        callee of a call (those are handled in :meth:`_check_call`).  There is no
        legitimate reason for sandboxed agent code to *reference* these names, so
        any such load is a CRITICAL finding.
        """
        if not isinstance(node.ctx, ast.Load) or id(node) in call_func_ids:
            return []
        if node.id in CRITICAL_BUILTINS:
            return [
                self._violation(
                    "CODE-EXEC",
                    f"Reference to a dynamic-execution builtin is forbidden: {node.id}",
                    Severity.CRITICAL,
                    node.id,
                )
            ]
        return []

    def _check_import(self, module: str, level: int, matched: str) -> list[Violation]:
        if not module:
            return []
        # M3: a relative import (``from .os import x``) addresses the local
        # package, not the absolute ``os`` — do not apply the absolute allowlist.
        if level and level > 0:
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
        # L12: flag a private module anywhere in the dotted path, INCLUDING the
        # root (``import _socket``), not just submodules of an allowed root.
        if any(part.startswith("_") for part in module.split(".")):
            out.append(
                self._violation(
                    "CODE-IMPORT-PRIVATE",
                    f"Access to a private module is not permitted: {module}",
                    Severity.MEDIUM,
                    matched,
                )
            )
        return out

    def _check_imported_members(
        self, module: str, level: int, names: list[ast.alias]
    ) -> list[Violation]:
        """M2: flag dangerous/private *members* pulled via ``from x import …``.

        ``from builtins import __import__`` and ``from os import _exit`` are
        invisible to a module-only check, so inspect each imported name.
        """
        out: list[Violation] = []
        prefix = "." * (level or 0)
        for alias in names:
            name = alias.name
            if name == "*":
                continue
            matched = f"from {prefix}{module} import {name}"
            if name in CRITICAL_BUILTINS:
                out.append(
                    self._violation(
                        "CODE-EXEC",
                        f"Dynamic code execution builtin is forbidden: {name}",
                        Severity.CRITICAL,
                        matched,
                    )
                )
            elif name in HIGH_DUNDERS:
                out.append(
                    self._violation(
                        "CODE-DUNDER-ACCESS",
                        f"Import of escape-vector attribute is forbidden: {name}",
                        Severity.HIGH,
                        matched,
                    )
                )
            elif name.startswith("_"):
                out.append(
                    self._violation(
                        "CODE-IMPORT-PRIVATE",
                        f"Import of a private member is not permitted: {name}",
                        Severity.MEDIUM,
                        matched,
                    )
                )
        return out

    def _check_call(
        self,
        node: ast.Call,
        alias_map: dict[str, str],
        builtin_aliases: dict[str, str] | None = None,
    ) -> list[Violation]:
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            # Resolve a builtin laundered through a local name (``rd = open``).
            builtin = (builtin_aliases or {}).get(name, name)
            if builtin in CRITICAL_BUILTINS:
                return [
                    self._violation(
                        "CODE-EXEC",
                        f"Dynamic code execution builtin is forbidden: {name}()",
                        Severity.CRITICAL,
                        f"{name}(...)",
                    )
                ]
            if builtin in HIGH_BUILTINS:
                return [
                    self._violation(
                        "CODE-DANGEROUS-BUILTIN",
                        f"Risky builtin call: {name}()",
                        Severity.HIGH,
                        f"{name}(...)",
                    )
                ]
            if builtin in MEDIUM_BUILTINS:
                # L2: getattr(o, "__globals__") is an escape vector, not noise —
                # promote to HIGH when the target is a dunder string literal.
                dunder = self._literal_dunder_arg(node) if builtin in _ATTR_BUILTINS else None
                if dunder is not None:
                    return [
                        self._violation(
                            "CODE-DUNDER-ACCESS",
                            f"Escape-vector attribute via {name}(): {dunder}",
                            Severity.HIGH,
                            f"{name}(..., {dunder!r})",
                        )
                    ]
                if self.flag_medium_builtins:
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
        if dotted is None:
            return []
        if dotted in self.dangerous_calls:
            return [
                self._violation(
                    "CODE-DANGEROUS-CALL",
                    f"Dangerous call is forbidden in generated code: {dotted}()",
                    Severity.CRITICAL,
                    f"{dotted}(...)",
                )
            ]
        # L3: resolve an aliased root (``o.system`` where ``import os as o``).
        head, _, rest = dotted.partition(".")
        if rest and head in alias_map:
            resolved = f"{alias_map[head]}.{rest}"
            if resolved != dotted and resolved in self.dangerous_calls:
                return [
                    self._violation(
                        "CODE-DANGEROUS-CALL",
                        f"Dangerous call (via alias '{head}') is forbidden: {resolved}()",
                        Severity.CRITICAL,
                        f"{dotted}(...) -> {resolved}",
                    )
                ]
        return []

    @staticmethod
    def _literal_dunder_arg(node: ast.Call) -> str | None:
        """Return a string-literal dunder argument (``__…``), else ``None``.

        Scans positional *and* keyword arguments: ``setattr(o, name='__dict__', …)``
        smuggles the dunder through the ``name=`` keyword, so inspecting only
        ``node.args`` would let it fall through to MEDIUM ``CODE-INTROSPECTION``
        instead of being promoted to HIGH ``CODE-DUNDER-ACCESS``.
        """
        candidates: list[ast.expr] = list(node.args)
        candidates.extend(kw.value for kw in node.keywords)
        for arg in candidates:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value.startswith("__"):
                    return arg.value
        return None

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
    "DEFAULT_MAX_CODE_SIZE",
    "HIGH_BUILTINS",
    "HIGH_DUNDERS",
    "MEDIUM_BUILTINS",
    "MEDIUM_DUNDERS",
    "CodeActionValidator",
]
