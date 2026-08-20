# Audit: the Z3 / Lean 4 verification surface

**Date:** 2026-08-19 · **Scope:** `src/acgs_lite/formal/smt_gate.py`, `src/acgs_lite/z3_verify.py`,
`src/acgs_lite/lean_verify.py`, and their call site in `src/acgs_lite/governed.py`
· **Status:** F0, F3 (partly), F4 and F5 fixed on `security/formal-verification-fail-closed`; see Resolution at the end.

The package advertises `formal-verification`, `z3`, and `lean4` as PyPI keywords
(`pyproject.toml:16`). This audit asks a narrow question of the code behind that claim: **when
these components report "verified", what has actually been proved?**

Four paths exist. One is real mathematics. One is a tautology. One evaluates a ground formula.
All of them return "allow" on every error path — and one of them runs rule text as Python
through a sandbox that does not hold.

---

## F0 — rule text reaches `eval` through a sandbox that does not hold

`z3_verify.py:53-59` documents a sandbox and names the exact threat it is meant to stop:

> Locked-down globals for evaluating policy expressions. eval() auto-injects the real builtins
> when given a globals dict without "__builtins__"; an empty mapping here blocks that, **so a
> policy string sourced from a constitution rule cannot reach `__import__`/`open`/etc.**

```python
_POLICY_EVAL_GLOBALS: dict[str, Any] = {"__builtins__": {}}
...
expr = eval(policy, _POLICY_EVAL_GLOBALS, eval_ctx)   # z3_verify.py:526 and 665
```

The comment is wrong. Emptying `__builtins__` blocks *name* lookup; it does not block
*attribute* lookup, and `eval_ctx` hands the expression live function objects — `And`, `Or`,
`Not`, `Implies`. Every Python function carries `__globals__`, so `And.__globals__` is the z3
module's global namespace, which has a fully populated `__builtins__`.

Executed against the real code path, with the marker file created as a side effect of
evaluating a rule:

```
payload = "And.__globals__['__builtins__']['open'](MARKER,'w').write(...) == 0 or amount < 500"

verified: True satisfiable: True error: None
--- side effect ---
arbitrary code ran from a constitution rule  <- file created by the policy string
```

No exception, no warning, and the verification result looks entirely normal.

Both call sites also carry `# noqa: S307 - sandboxed builtins`, so the linter rule that exists
to catch exactly this is suppressed on the strength of the same incorrect claim.

**Reachability — traced, and narrower than it first looks.** `_extract_z3_policies`
(`z3_verify.py:737`) takes these strings from `rule.text` (any rule whose text begins `z3:` or
`smt:`) and from the `z3_expression` / `smt_constraint` metadata keys. It has exactly one call
site: `governed.py:652`, reading `self.constitution` — the object the application passed to
`GovernedAgent`, defaulting to `Constitution.default()` (`governed.py:152`).

The HTTP lifecycle path does **not** reach it. `POST /{bundle_id}/eval` runs a bundle's rules
through `GovernanceEngine` (`lifecycle_service.py:465`), which contains no z3 references at all,
and no code wires an activated bundle into a `GovernedAgent`'s constitution. So this is not a
remote-authenticated RCE.

What it is: **rule text is `eval`'d, and the constitution is treated as trusted config.**
`governed.py:199-206` says so directly — "Only trusted content (rule IDs, rule text from the
constitution)". That trust model is coherent as long as constitutions only ever come from a
file the operator wrote. The defect is that the code claims a second line of defence it does
not have, so the moment any less-trusted input becomes rule text — a synced or fetched
constitution, a bundle promoted from the lifecycle API into an application-constructed
`GovernedAgent`, a multi-tenant deployment where tenants supply rules — it is code execution,
not a policy violation.

Also gated on `Z3_AVAILABLE`, so a default install (no `z3-solver`, see F4) cannot reach the
`eval` at all. It becomes reachable the moment the solver is installed, which is exactly what
adopting the advertised feature requires.

**Fix direction.** Do not `eval` policy strings. Parse them with `ast.parse` and walk the tree
against an explicit allowlist of node types (`Compare`, `BoolOp`, `Name`, `Constant`, `Call`
restricted to the four z3 helpers), rejecting `Attribute`, `Subscript`, and everything else
outright. An allowlist over the AST is checkable; a denylist over `eval` globals is not.

---

## F1 — `Z3VerificationGate.check()` asks a question unrelated to the rule

`formal/smt_gate.py:70-73`

```python
solver = self._z3.Solver()
keyword_symbols = [self._z3.Bool(f"kw_{index}") for index, _ in enumerate(rule.keywords)]
solver.add(self._z3.Or(*keyword_symbols))
satisfiable = solver.check() == self._z3.sat
```

The `kw_i` are **fresh, unconstrained** boolean variables. The keyword *strings* are never
encoded — only their count reaches the solver, and even the count is irrelevant: a disjunction
of free booleans is satisfiable for any n ≥ 1 (set any one true). Z3 is invoked and does real
work; it answers a question with no relationship to the rule.

So `satisfiable` is a **constant**. Proven against z3 5.1.0:

```
z3 available to the gate: True
  benign                 keywords=  2  satisfiable=True
  dangerous              keywords=  2  satisfiable=True
  self-contradictory     keywords=  2  satisfiable=True
  one keyword            keywords=  1  satisfiable=True
  50 keywords            keywords= 50  satisfiable=True
  garbage                keywords=  3  satisfiable=True

  distinct satisfiable values across all cases: {True}
  formula asserted: Or(kw_0, kw_1, kw_2)
  solver result:    sat
```

The no-keywords and no-z3 branches (lines 50-68) also return `satisfiable=True`, so the field
is `True` on every path through the function.

The one part of `check()` with real content is `contradiction` (lines 44-48) — a plain Python
scan for a duplicate rule id carrying a different severity. No SMT involved.

**Impact is bounded:** this class is not wired to enforcement. Its only consumer is
`commands/eval_cmd.py:139`, which prints the value in a report column. It is, however,
exported from the package root as `Z3VerificationGate` (`__init__.py:113`), so callers can
reasonably read the name as a gate.

## F2 — `_build_action_constraints` builds a ground formula

`z3_verify.py:136-155`

All six principle variables are pinned by equality to values already computed in Python:

```python
solver.add(data_destruction == is_destruction)
solver.add(system_escalation == is_escalation)
...
```

With every variable determined, the formula has exactly one model and the solver performs no
search. This is equivalent to evaluating

```python
(is_destruction and is_production) or is_secret or is_bypass \
    or (is_financial and is_production) or (is_escalation and is_production)
```

The polarity is handled **correctly** — `sat` maps to `satisfiable=False` (`z3_verify.py:243`),
matching the comment that the negation of the acceptable condition is asserted. This is not a
soundness bug; it is a cost and a claims issue. What `_extract_counterexample` returns is not a
counterexample in the SMT sense (there is no space of assignments to witness), but it is not
worthless either: filtering `v is not False` leaves exactly the violation predicates that
fired, which is a usable diagnostic.

## F3 — the callable verifier is real, with two caveats

`verify_callable_safety` (`z3_verify.py:477`) is genuine SMT: `parse_callable_to_z3` builds
free `Int`/`Real`/`String` variables from type hints and `annotated_types`/Pydantic metadata,
asserts the type-hint constraints, then asserts `Or(Not(p) for p in policies)`. SAT means a
type-valid input exists that violates a policy. That is the right question, correctly posed.

Two limits worth recording:

- **`Real` is not `float`.** `_parse_type_and_constraints` maps `float` to `z3.Real`
  (`z3_verify.py:331`), which is an exact rational. A property proved over the rationals does
  not transfer to IEEE-754: rounding, overflow, signed zero, and NaN are all outside the model,
  and NaN in particular makes every comparison false. `unsat` here means "safe over the
  rationals", which is weaker than "safe at runtime".
- **`annotated_types.Interval` loses constraints.** The `elif` chain at `z3_verify.py:359-370`
  tests `hasattr(m, "gt")`, then `ge`, `lt`, `le`. `Interval` carries all four attributes, so
  the first matching branch wins and the rest are dropped: `Interval(gt=0, lt=10)` encodes only
  `> 0`. This under-constrains the input space, which errs toward *more* reported violations —
  imprecise rather than unsound, but it means a reported counterexample may be unreachable.

## F4 — the Z3 layer is fail-open by construction

Every failure mode in `verify_callable_arguments` — the function `governed.py` calls at
runtime — returns `satisfiable=True, verified=False`:

| Condition | Line | Result |
|---|---|---|
| `z3-solver` not installed | 611 | `verified=False` |
| No type-hinted parameters | 623 | `verified=False` |
| No policy string parsed | 680 | `verified=False` |
| Solver returns `unknown` / timeout | 721 | `verified=False` |
| Any exception | 724 | `verified=False` |

`verify_callable_safety`, used for the static pass at `governed.py:657`, has the same five
exits at lines 497, 509, 541, 580, and 583.

The enforcement site blocks only on the conjunction (`governed.py:691`, and again at 731):

```python
if runtime_res.verified and not runtime_res.satisfiable:
    raise ConstitutionalViolationError(...)
```

`verified=False` therefore means **execute**. Every degradation path allows the action.

Two consequences follow.

**A one-character typo in a policy silently disables enforcement.** Both runs below call
`transfer(amount=10000)` against the policy `amount < 500`:

```
  well-formed policy
    extracted policies : ['amount < 500']
    verified           : True
    satisfiable        : False
    -> governed.py raises ConstitutionalViolationError? True

  malformed policy
    extracted policies : ['amount << 500']
    verified           : False
    satisfiable        : True
    error              : No valid safety policies found
    -> governed.py raises ConstitutionalViolationError? False
```

The only signal is `_log.warning("Failed to parse policy string ...")` at `z3_verify.py:668`.
Policy strings come from rule text and rule metadata via `_extract_z3_policies`
(`z3_verify.py:737`), i.e. from the constitution — the document least likely to be exercised by
a test that would surface the warning.

**In a default install this path is taken 100% of the time.** There is no `z3-solver`
dependency in `pyproject.toml` — not in `[project.dependencies]`, not in any extra. `z3` is a
marketing keyword only. `Z3_AVAILABLE` is therefore `False` for every user who does not install
the solver by hand, and `governed.py:654` skips the whole block.

For a project whose stated invariant is fail-closed behavior, Layer 3 fails open on every
error path. Of the findings that do not require an attacker, this is the one that most changes
what a user of this library is actually protected by.

## F5 — Lean accepts an unchecked proof when the kernel is absent

`_run_lean_check` is correctly fail-closed — no Lean binary yields `(False, [...])`
(`lean_verify.py:386-391`) — and its docstring is explicit:

> This is the TRUST BOUNDARY. If this returns True, the proof is machine-verified — not
> LLM-generated-and-hoped-for.

Its caller bypasses that boundary (`lean_verify.py:744-747`):

```python
else:
    # No kernel — accept the generated proof but mark as unverified
    _log.info("Lean not installed — proof generated but not kernel-verified")
    return True, proof_body, ["lean not installed"], attempt
```

`verify()` then takes the `proved and proof_body` branch and mints a `ProofCertificate` with a
`proof_hash` over source no kernel ever read, returning `proved=True, verified=True`.

This is **documented, not hidden**: `kernel_verified` is computed honestly as `False`
(`lean_verify.py:823`), the field is carried into `to_audit_dict()`, and the module docstring
and class docstring both say the result will show `kernel_verified=False`. The gap is that the
two headline fields — `proved` and `verified` — both read `True`, and a certificate object
exists at all. A consumer checking the obvious field gets the wrong answer; only the third
field tells the truth.

Also worth noting: the vacuous-theorem branch at `lean_verify.py:539`
(`theorem_goal = ... if predicate_refs else "True"`) is **unreachable** — `verify()` returns
early at line 793 when `predicates` is empty, and a non-empty `predicates` always yields a
non-empty `predicate_refs`. Dead defensive code, not a live vacuous-proof path.

---

## What to do

Ranked. None applied — F4 changes fail-closed behavior on a governance path and needs sign-off
plus negative-path tests per `.claude/rules/security-sensitive-files.md`.

0. **F0, first.** Replace `eval` with an AST-allowlist parser. This is the only finding here
   that lets a rule author run code, and it needs a test that a policy containing `Attribute`
   or `Subscript` nodes is rejected rather than evaluated.
1. **F4, requires approval.** Decide what `verified=False` means. The options are a strict mode
   that raises when a policy exists but cannot be evaluated, or an explicit documented
   allow-with-alarm. Either way an unparseable policy string should not be a WARNING log — it
   is a broken control, and the constitution that carries it should fail validation at load
   time, not at first call. Any change here needs tests proving the side effect did *not* run.
2. **F4b, low risk.** Declare `z3-solver` in an extra (e.g. `[project.optional-dependencies] z3`)
   so the advertised capability is installable, and make the PyPI keywords match what a default
   install provides.
3. **F1.** Either encode rule content into the SMT problem or rename the class and stop
   returning a `satisfiable` field that is constant. As written the name overstates it.
4. **F3.** Replace the `hasattr` chain with explicit `annotated_types` handling so `Interval`
   contributes all its bounds; document the `Real`-vs-`float` gap where the API is described.
5. **F5.** Report `proved=False`, or add a distinct status, when no kernel ran — or at minimum
   stop constructing a `ProofCertificate` for a proof nothing checked.

## Reproducing

`z3-solver` is not a declared dependency, so it must be installed by hand first:

```bash
uv pip install --python <venv> z3-solver
```

The probe that produced the F1 and F4 output above was written to a scratch directory and is
not checked in; both results are reconstructable from the snippets quoted in those sections.

F0, F1, and F4 were executed against z3 5.1.0 on Python 3.11.14. F5 was read from source, not
executed — it requires `mistralai` plus a Lean toolchain.


---

## Resolution

Fixed on `security/formal-verification-fail-closed`. Behavior recorded here as it was found;
this section says what changed, so the two are not confused.

| Finding | Status | Where |
|---|---|---|
| F0 `eval` sandbox | **Fixed** | `formal/policy_ast.py` — AST allowlist replaces `eval` |
| F4 fail-open gate | **Fixed** | `VerificationStatus` + `blocks_execution()`; policies extracted unconditionally; `PASS` is the only allowing status |
| F4c `INAPPLICABLE` allowed | **Fixed** | blocks; `formal/exemption.py` is the explicit, expiring, audited escape |
| F4b undeclared dep | **Prepared, not applied** | `pyproject.toml` is hash-sealed; the `z3` extra needs a human-applied edit |
| F5 unchecked Lean proof | **Fixed** | no kernel → `proved=False`, `certificate=None`, candidate in `proposed_proof` |
| F3 `Real` vs `float`, `Interval` | **Documented, not changed** | `docs/formal-verification.md` § Limits |
| F1 tautological gate | **Documented, not changed — reachability now confirmed worse** | see below |
| F2 ground formula | **Documented, not changed** | not a soundness bug |

Every verifier error state now blocks. Demonstrated against the real predicate:

```
PART 1 - verifier status -> gate decision
  state                                status          decision
  --------------------------------------------------------------
  compliant call                       pass            allow
  violating call                       fail            BLOCK
  malformed policy                     invalid_policy  BLOCK
  sandbox-escape policy                invalid_policy  BLOCK
  partially bound policy               invalid_policy  BLOCK
  no type hints                        inapplicable    BLOCK
  policy about another callable        inapplicable    BLOCK
  solver returns unknown               unknown         BLOCK
  solver raises                        error           BLOCK
  z3-solver not installed              unavailable     BLOCK

PART 2 - exemptions, through GovernedCallable
  inapplicable, no exemption                           BLOCK (Z3 verification could not clear this cal)
  inapplicable, exemption below @GovernedCallable      allow
  inapplicable, exemption ABOVE (wrong order)          BLOCK (Z3 verification could not clear this cal)
  FAIL with a valid exemption                          BLOCK (Action violates mathematical constraints)
  INVALID_POLICY with a valid exemption                BLOCK (at decoration)
  UNKNOWN with a valid exemption                       BLOCK (Z3 verification could not clear this cal)
  ERROR with a valid exemption                         BLOCK (Z3 verification could not clear this cal)
  UNAVAILABLE with a valid exemption                   BLOCK (Z3 verification could not clear this cal)
```

Two of those rows are worth reading closely. `INVALID_POLICY` never reaches the runtime
gate at all: `GovernedCallable.__call__` parses every Z3 policy when the decorator is
applied, so a constitution containing a malformed policy refuses the *decoration* and the
callable does not come into existence. An exemption cannot be consulted because there is
nothing to exempt. And `UNAVAILABLE` is decided before applicability is computed, so on an
install without `z3-solver` a governed callable blocks whether or not it carries an
exemption — the escape hatch is for "verification ran and had nothing to say", not for
"verification did not run".

`INAPPLICABLE` was, for one round of this work, a deliberate allow: a constitution's
policies are global while callables are many, so a policy naming none of a callable's
parameters was treated as having nothing to say about it. That was reported as a knowing
deviation from "any verification uncertainty blocks", and it was overruled.

It is now a **block**. The argument that settled it: the same status is produced when a
callable has no type hints at all, because policy variables are built from hints and an
unannotated callable binds none. From inside the verifier "this policy is about another
function" and "this function has no annotations, so no policy can bind to it" are the same
observation. Allowing on it means an ordinary refactor that drops a `: int` moves a callable
outside its own control with no diagnostic — a gate that can be switched off by deleting an
annotation.

Execution without verification is still reachable, but it now has to be declared:
`@verification_exempt` in `formal/exemption.py` requires a reason, an approver, and a
timezone-aware deadline no more than 365 days out; it is refused at decoration time if any
of those is missing, naive, past, or over-horizon; and every use writes a
`verification_exemption` entry to the audit chain before the call proceeds. It clears
`INAPPLICABLE` and nothing else — verification runs first, so an exempt callable still takes
its `FAIL` — and applying it above `GovernedCallable` instead of below marks the wrapper
rather than the function the gate holds, which denies rather than grants.

A policy naming *some* of a callable's parameters remains `INVALID_POLICY` and blocks: a
half-bound policy cannot be evaluated, and skipping it is how enforcement disappears.

### F1 is reachable from a user-facing command, and that command can never fail

Re-checked while closing this series. `Z3VerificationGate` is not dead code: `acgs eval
verify-constitution` (`commands/eval_cmd.py:127`) builds one and reports a table of
`satisfiable` / `contradiction` per CRITICAL rule, exiting non-zero
`if any(result.contradiction for result in results)`.

Neither field depends on the rule. Actual output of the command:

```
$ python -m acgs_lite.cli eval verify-constitution
rule_id          satisfiable  contradiction  warnings
ACGS-001         True         False          -
ACGS-003         True         False          -
ACGS-004         True         False          -
ACGS-006         True         False          -
$ echo $?
0
```

Both columns are constants, and each for its own reason.

`satisfiable` — the gate never translates the rule into a constraint. It allocates one fresh
boolean per keyword and asserts their disjunction:

```
  N=1: assert Or(kw_0)                              ->  check() == sat
  N=2: assert Or(kw_0, kw_1)                        ->  check() == sat
  N=5: assert Or(kw_0, kw_1, kw_2, kw_3, kw_4)      ->  check() == sat
```

`Or` over unconstrained fresh booleans is satisfiable for any non-empty keyword list, and the
empty case returns a hardcoded `satisfiable=True` before the solver is reached. The rule text
is not an input. A rule written to contradict itself reports the same as any other:

```
  SELF-CONTRA  satisfiable=True  contradiction=False  warnings=('rule has no keywords; SMT verification skipped',)
```

`contradiction` — it is not a logical check at all. It is true only when two rules share an
`id` with different severities, and `Constitution` rejects that at construction:

```
  duplicate ids REFUSED by Constitution: ValidationError: 1 validation error for Constitution
  Value error, Constitution validation failed: ['Duplicate rule ID: DUP']
```

So the CLI's exit condition, `any(result.contradiction for result in results)`, is
unreachable by construction rather than merely false in practice.

`acgs eval verify-constitution` therefore always prints a clean table and always exits 0. It
is not an execution gate — nothing routes through it to decide whether a call runs, so it
cannot permit an unsafe action — but it is an *assurance* surface that reports success
unconditionally, which is the same class of defect as F4 in a place a human reads rather than
a place the runtime reads.

Left unchanged deliberately: making it mean something requires deciding what a rule's
semantics are in SMT, which is a design task rather than a hardening fix, and changing the
command's exit code would break any pipeline currently consuming it. It is called out here
and in `docs/formal-verification.md` so the name is not read as a guarantee. **It should not
ship as-is in a release that advertises formal verification.**

### The fix had to be visible to CI, not only to a developer with z3 installed

No CI lane installed `z3-solver`, so `Z3_AVAILABLE` was `False` everywhere in CI. Two
consequences, both fixed here:

- `tests/test_z3_fail_closed.py` used a module-scope `pytest.importorskip("z3")`, so all of
  its cases **skipped silently in every CI job** — the file that proves the fix would have
  been dark in the only place it is run automatically. The guard is now per-test, applied
  only to cases that need real solving. In the z3-less configuration the module goes from
  1 collection-skip to **14 passing tests**, including the missing-solver block and both
  decoration-time rejections.
- `test`, `coverage`, and `governance-regression` now install `z3-solver`, so the solver
  paths are exercised. `python-fallback` deliberately does **not**, which makes it the lane
  that proves `UNAVAILABLE → block`; a comment there says so, because the obvious way to
  "fix" a failure in that lane is to install z3 and thereby delete the test.

Both configurations are green on this branch — see the commit message for the literal counts.
