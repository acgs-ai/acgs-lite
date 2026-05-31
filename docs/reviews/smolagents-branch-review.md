Both claims verified against source. The findings are accurate. Here is the synthesis report.

# Branch Review: `feature/smolagents-integration`

## 1. Verdict

**block** — two independently-reachable fail-open governance bypasses (strict=False executor gate, RecursionError-escapes-guard) defeat the headline "block before it runs" guarantee.

## 2. Constitutional Invariant Scorecard

| Invariant | Rating | Evidence |
| --- | --- | --- |
| **CK-001** lazy imports | **FAIL (minor)** | `import smolagents` runs at module-import time inside guarded try/except to set `SMOLAGENTS_AVAILABLE` (`smolagents.py:54-59`), contradicting the module's own docstring "smolagents is not imported at module load" (`smolagents.py:22-24`). The hard dep `from smolagents import CodeAgent` is correctly deferred (`smolagents.py:245`). Use `importlib.util.find_spec`. |
| **CK-002** validate-raises | **FAIL** | The contract holds inside the engine, but the executor wrapper undermines it: `GovernedPythonExecutor.__call__` discards the `validate_code` return and unconditionally delegates (`smolagents.py:82-83`). Under `SmolagentsGovernor(strict=False)` a BLOCK finding returns `valid=False` instead of raising, and the dangerous code still runs. |
| **CK-003** derived hash | **PASS** | The adapter never constructs or mutates a `ConstitutionBundle`; `_const_hash` is read from `constitution.hash` inside the engine (`core.py:103`). No deviation surface in this diff. |
| **MACI not bypassed** | **PASS** | Neither new file imports `acgs_lite.maci`, enforcer, registry, or roles (grep-confirmed empty). No MACI surface touched. |
| **matcher hot-path** | **PASS** | `matcher.py` is untouched and does not import `code_analysis`/`smolagents`. The AST analyzer imports only `ast`, `Severity`, `engine.models.{CustomValidator,Violation}` (`code_analysis.py:30-35`) and plugs in solely via `engine.add_validator(...)` (`smolagents.py:118`). No shared-state perturbation. |
| **agent-native parity** | **FAIL** | Governance is asymmetric across seams: the executor passes `context={"action_type":"code"}` so the AST validator fires (`smolagents.py:131`), but `final_answer_check`/`step_callback` route through `_validate_nonstrict` with no context (`base.py:92-96`), so the AST validator's trigger gate (`code_analysis.py:361-364`) returns `[]` and never analyzes step code. Non-strict hooks also raise on HALT, contradicting their documented "never raises" contract (`smolagents.py:141-174` → `core.py:491-496`). |
| **docs-parity** | **FAIL** | `examples/ai-agent-instructions.md:38` references `gov_decision.decision`, which does not exist on `ValidationResult` (`models.py:34-53`) — the copy-paste template raises `AttributeError` on the first violation. Module docstring also claims no import at load (contradicted by CK-001 above). |

## 3. Findings by Severity

### HIGH

**H1. Fail-open: `strict=False` governor turns the pre-execution gate into an audit-only no-op** — `smolagents.py:80-83, 122-133`
`__call__` calls `self._gov.validate_code(code_action)` and discards the result (line 82), then unconditionally runs `self._inner(...)` (line 83). `validate_code` passes `strict=None`, which resolves to instance strictness (`core.py:916`). The public constructor accepts `strict=False` (`smolagents.py:105`); in that mode the engine returns `valid=False` rather than raising (`core.py:501-508`), so AST-detected `eval`/`os.system`/`subprocess` executes with only an audit record. This is a governance bypass reachable purely through the public constructor.
**Fix:** Make the pre-exec gate independent of engine strictness — either force `validate_code(code_action, strict=True)`, or capture the result and `raise ConstitutionalViolationError` when `not result.valid` before delegating.

**H2. RecursionError escapes the parse/walk guard → ungoverned action + DoS (reproduced on project runtime)** — `code_analysis.py:218-224`
`analyze()` guards only `(SyntaxError, ValueError)` and `ast.walk` runs unguarded. On the project `.venv` (Python 3.11, recursionlimit 1000), deeply-nested valid expressions (`'x' + '.a'*5000`, `'x' + '+x'*60000`, deep subscripts/boolops) raise `RecursionError` out of `analyze()`. End-to-end confirmed: `SmolagentsGovernor(strict=True).validate_code('x' + '.a'*5000)` returns `valid=True` with only a non-blocking `CUSTOM-ERROR/MEDIUM` (engine downgrade at `core.py:1084-1095`), and a `.__subclasses__` payload reached via a deep attribute chain also returns `valid=True` instead of the `CODE-DUNDER-ACCESS` (HIGH) it would otherwise emit. An attacker pads a dangerous expression with benign nesting to defeat the entire AST layer.
**Fix:** Broaden the guard to `except (SyntaxError, ValueError, RecursionError, MemoryError)`, and for this security-bearing path **fail closed** — emit a blocking Violation on parse/walk failure rather than `[]`. Add a pre-parse size cap.

**H3. Fail-open: unparseable code actions execute ungoverned (analyzer swallows parse errors)** — `code_analysis.py:218-221`
`analyze()` returns `[]` on any `SyntaxError`/`ValueError`. The AST analyzer is the *only* governance the wrapper adds in front of the executor (no sandboxing of the inner executor). Any input `ast.parse` rejects but smolagents' own compile/exec can run (or future grammar divergence, NUL-byte `ValueError`, etc.) executes completely ungoverned — directly undermining the docs' "blocking (strict)" claim.
**Fix:** Treat an unparseable code action as a blocking violation in the code path (emit `CODE-UNPARSEABLE` CRITICAL/HIGH when triggered with `action_type=="code"`). Reserve `[]` for non-code contexts only.

### MEDIUM

**M1. Non-blocking hooks raise on HALT, breaking their "never raises" contract** — `smolagents.py:141-174`
`final_answer_check` and `step_callback` both delegate to `_validate_nonstrict` → `engine.validate(..., strict=False)` with no exception handling (`base.py:92-96`). But `_raise_for_enforcement` raises on `primary_action is HALT` *regardless of strict* (`core.py:491-496`, evaluated before the `if strict and ...` branch). A constitution `Rule(workflow_action="halt")` matching a final answer or step content therefore tears down the run instead of returning `False`/recording-and-continuing. Docstrings explicitly promise "never raises" / "non-blocking by design" (`smolagents.py:144-147, 160-161`; `docs/research/smolagents-adaptation.md:44-45`).
**Fix:** Wrap the `engine.validate` call in `_validate_nonstrict` with `try/except ConstitutionalViolationError: logger.warning(...); return None`, and add a regression test using a `workflow_action="halt"` rule.

**M2. `from … import …` never inspects imported member names** — `code_analysis.py:228-231, 247-280`
The `ImportFrom` branch passes only the module name to `_check_import`; member names (`node.names[*].name`) only feed the human-readable `matched` string. So `from builtins import __import__`, `from os import _exit`, `from json import __builtins__`, and `from <authorized> import _secret` produce zero member-level findings. The shipped test only covers `import random._os` (a dotted *module*), so this is untested.
**Fix:** Iterate `node.names` and run private/dunder/critical-builtin checks against each `alias.name` in addition to the module-level check; add tests for `from x import _priv` and `from x import __import__`.

**M3. AST analyzer ignores relative-import depth (`node.level`)** — `code_analysis.py:228-231`
`node.level` is never read, so a relative import is matched against the *absolute* allowlist: `from .os import helper` (level=1) → root `os` ∈ `CRITICAL_IMPORTS` → `CODE-IMPORT-CRITICAL` (blocking); `from .utils import x` → `CODE-IMPORT-FORBIDDEN` (HIGH, blocking). Safe intra-package code is hard-blocked with a misleading rule_id, and the absolute allowlist is mis-applied to a namespace it does not describe.
**Fix:** When `node.level > 0`, treat as a relative/intra-package import and skip the absolute critical/allowlist classification (apply a separate relative-import policy, or none).

**M4. `wrap()` silently fails open on non-list hook sequences (e.g. tuple)** — `smolagents.py:208-226`
`_append_hook` handles only `None` and `list`; any other shape logs a warning and attaches *nothing*, yet `wrap()` still returns the agent as governed (`smolagents.py:191`). An agent exposing `final_answer_checks`/`step_callbacks` as a tuple gets no final-answer check and no step audit hook — a silent fail-open. Untested non-list path.
**Fix:** Coerce non-list sequences via `existing = list(existing); setattr(...); existing.append(hook)`, or surface a hard failure so callers are not misled.

**M5. `final_answer_check` raises when the answer's `__str__` raises** — `smolagents.py:149-152`
`str(final_answer)` runs outside the guarded `_validate_nonstrict` path. An answer object whose `__str__` raises propagates the exception out of the hook (verified: raised `ValueError` instead of returning a bool), contradicting the "never raises" contract.
**Fix:** Wrap `str(final_answer)` in try/except with a `repr()`/placeholder fallback; treat a failed coercion as a non-blocking pass-through. Check `_first_str_attr` similarly.

**M6. `__getattr__` forwards inner executor's callable execution methods ungoverned** — `smolagents.py:80-89`
The gate lives only in `__call__`. `__getattr__` blanket-forwards every other attribute to `self._inner`; smolagents executors commonly expose `run`/`execute`/`run_code` and state-mutating entry points. Any path reaching those runs code that never passes `validate_code`.
**Fix:** Whitelist non-executing attributes to delegate and intercept every known execution method, or assert at wrap time that `__call__` is the inner executor's only execution entry point for the detected smolagents version.

**M7. Custom-validator skip-if-CRITICAL gate drops AST findings from the audit trail** — `core.py:904-908`
Custom validators run only when no CRITICAL constitution violation already fired. When a CRITICAL keyword/regex rule matches a code action, the AST analyzer is skipped entirely — the action is still blocked, so not a fail-open, but the audit record omits the dangerous imports/exec/dunder access the AST would have logged, a forensic-completeness gap for an audit-backed product.
**Fix:** Collect custom-validator violations unconditionally and use the CRITICAL short-circuit only for the enforcement decision, not collection; or document the best-effort behavior and add an asserting test.

**M8. Same code action audited under divergent `agent_id` identities** — `smolagents.py:128-133, 156-174`
The executor seam audits as `f"{agent_id}:code"`, while the step seam audits the same code under `f"{agent_id}:smolagents step code"` (and `:smolagents step output`, `:smolagents final answer`) via `_validate_nonstrict` (`base.py:94`). One logical agent scatters across ≥4 `agent_id` strings, while `governance_stats` reports only the bare `agent_id` — any per-agent audit aggregation under-counts or fails to correlate.
**Fix:** Adopt one consistent `agent_id` scheme across seams (e.g. `:code` for code in both executor and step-code branch; stable `:final`/`:output` labels) and document it.

### LOW

**L1. CK-001: `import smolagents` at module load** — `smolagents.py:54-59`. Probe via `importlib.util.find_spec("smolagents")` instead; fixes the docstring-parity contradiction (`smolagents.py:22-24`).

**L2. `getattr`/`setattr`/`delattr` are MEDIUM (WARN, non-blocking) and string-literal dunder targets are invisible** — `code_analysis.py:57-59, 244-252`. `getattr(getattr({},'__class__'),'__bases__')` yields only a non-blocking `CODE-INTROSPECTION` MEDIUM. Promote to HIGH when arg 2 is a string literal starting with `__`, or document the WARN-only choice.

**L3. Dangerous-call detection is name-bound, evaded by aliasing** — `code_analysis.py:70-85, 284-293`. `import os as o; o.system(...)` → `o.system` ∉ `DANGEROUS_CALLS`. Default config still blocks via import allowlist, but a customized allowlist relying on `DANGEROUS_CALLS` is bypassed. Resolve aliases during the walk; document as defense-in-depth.

**L4. No input-size bound before `ast.parse`+`ast.walk` on the blocking hot path** — `code_analysis.py:216-235`. Unbounded O(n) per action, re-paid 2-3x per step (executor + step_callback + final_answer). Add a pre-parse length cap; avoid re-analyzing in `step_callback` what the executor already validated.

**L5. `analyze()` raises `TypeError` on non-str/non-bytes actions; bytes take an unintended code path** — `code_analysis.py:209-221`. Confirmed: `analyze(123)`/`analyze(['import os'])` raise `TypeError` (escapes the guard → `CUSTOM-ERROR` MEDIUM downgrade); `analyze(b'import os')` parses and flags `CODE-IMPORT-CRITICAL`. Add `if not isinstance(code, str): return []` (or include `TypeError`); decide bytes handling intentionally.

**L6. `build_governed_code_agent` cannot configure the AST allowlist** — `smolagents.py:229-255`. The public builder forwards `**code_agent_kwargs` to `CodeAgent` but constructs `SmolagentsGovernor` without `code_validator`, so `authorized_imports`/`extra_authorized_imports`/`critical_imports` (the analyzer's primary tuning knob) are unreachable. Add a `code_validator` param and forward it.

**L7. `analyze_code=False` silently reduces code governance to string rules with no audit visibility** — `smolagents.py:116-118, 234, 247-252`. When disabled, the AST validator is never registered; no WARNING is logged and `governance_stats`/`stats` give no indication. Log a WARNING, surface `analyze_code` in stats, and document in the builder.

**L8. `wrap()` appends hooks with no dedup, contradicting documented idempotency** — `smolagents.py:178-191, 208-226`. The executor swap is guarded but the two hook installs are not; calling `wrap()` twice double-validates and writes duplicate SHA256-chained `AuditEntry` records, inflating `total_validations`. Tag closures with the owning governor and skip re-append, or correct the docstring.

**L9. `final_answer_check` coerces structured answers via `str()`, content can bypass matching** — `smolagents.py:149-152`. A dict/object `repr` may not contain the targeted substrings/regex, so a violating answer passes. Normalize deterministically (e.g. `json.dumps(..., default=str)`) or document the limitation; consider fail-closed on non-renderable answers.

**L10. Non-HALT BLOCK violations on final-answer/step content are advisory only** — `smolagents.py:141-174`. Under `strict=False`, BLOCK (non-HALT) findings on agent *output* are surfaced only as a `False` return smolagents may ignore (final answer) or recorded-but-not-acted-on (step). Output governance is delegated outside ACGS-Lite. Document explicitly, or escalate BLOCK-severity final-answer violations to a hard rejection.

**L11. Step/final-answer seams pass no `context`, so the AST validator never fires on produced content** — `base.py:92-96`. `_validate_nonstrict` omits `context=`, so the trigger gate (`code_analysis.py:361-364`) returns `[]` even though `step_callback` feeds it the step's `code_action` (`smolagents.py:165-167`). Have `_validate_nonstrict` accept/forward a `context` dict; pass `{"action_type":"code"}` for step code, or document the exclusion.

**L12. Private C-accelerator modules bypass the CRITICAL tier and private-submodule check** — `code_analysis.py:251-271`. `_ctypes`/`_socket`/`_posixsubprocess` aren't in `CRITICAL_IMPORTS` → fall to HIGH; and `module.split('.')[1:]` excludes the root, so a private *top-level* import is never flagged `CODE-IMPORT-PRIVATE`. Default config still blocks (HIGH), but severity is understated and a HIGH→warn deployment loses the block. Add private twins to `CRITICAL_IMPORTS` and/or include the root in the private scan.

**L13. docs-parity: `examples/ai-agent-instructions.md:38` references nonexistent `ValidationResult.decision`** — copy-paste template raises `AttributeError` on the first violation (sibling `.violations[0].rule_id` on line 37 is correct). Use `action_taken`/`violations[0].rule_id`; run the snippet before publishing. (Untracked file, pre-existing core API, flagged per the brief's instruction to check `examples/`.)

### Test-coverage gaps (LOW)
- **T1** `final_answer_check` rejection path (return `False`) is entirely untested — both tests feed clean answers (`tests/test_smolagents_integration.py:118-125`). Add a violating-answer test asserting `check(bad) is False`.
- **T2** MEDIUM→WARN→non-blocking is untested end-to-end through the strict executor (`tests/test_smolagents_integration.py:61-112`). Add a MEDIUM-only code test (e.g. `getattr(obj,'x')`) asserting no raise and `inner` IS called.
- **T3** `as_engine_validator` exception-safety isn't tested through the closure (`tests/test_code_analysis.py:108-123`). Add `assert CodeActionValidator().as_engine_validator()('def f(:', {'action_type':'code'}) == []`.

## 4. Top 3 Fixes to Do First

1. **Close the `strict=False` executor bypass (H1).** In `GovernedPythonExecutor.__call__`, force the pre-exec gate strict or check `result.valid` and raise before delegating — pre-execution code enforcement must not be downgradable via the engine-wide strict flag.
2. **Fail closed on unanalyzable code (H2 + H3).** Broaden the `analyze()` guard to catch `RecursionError`/`MemoryError`/`TypeError`, add a pre-parse size cap, and emit a **blocking** violation on parse/walk failure for the `action_type=="code"` path instead of returning `[]`.
3. **Honor the "never raises" hook contract (M1).** Wrap `_validate_nonstrict`'s `engine.validate` in `try/except ConstitutionalViolationError` (returning `None`) so `final_answer_check`/`step_callback` cannot crash the agent loop on a HALT rule; add a `workflow_action="halt"` regression test.