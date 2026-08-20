# Formal verification: what it checks, and what it does when it can't

acgs-lite has two optional formal-verification layers. Both are **off unless you install
their dependency**, and both **block rather than allow** when they cannot reach a verdict.

This page states exactly what each one proves, so that "verified" is not read as more than
it is.

## Availability

| Layer | Dependency | Installed by default? |
|---|---|---|
| Z3 SMT (`acgs_lite.z3_verify`) | `z3-solver` | **No** — `pip install z3-solver` |
| Lean 4 (`acgs_lite.lean_verify`) | `mistralai` **and** a Lean toolchain | **No** — `pip install "acgs-lite[mistral]"` plus `elan install` |

`z3` and `lean4` appear in the package keywords. They describe optional capabilities, not
what a default install gives you.

## The Z3 layer

### What it checks

A rule whose text begins `z3:` or `smt:`, or which carries a `z3_expression` /
`smt_constraint` metadata key, contributes a **policy** — a predicate over the parameters of
a governed callable. On each call the solver is asked whether the concrete arguments can
satisfy the type-hint constraints while violating any policy. If such an assignment exists,
the call is blocked and the assignment is reported as a counterexample.

### The policy language

Policies are parsed by a restricted AST allowlist (`acgs_lite.formal.policy_ast`), **not**
evaluated as Python. The accepted grammar:

- comparisons: `< <= > >= == !=`, including chained forms (`0 < amount < 500`)
- boolean connectives: `and`, `or`, `not`, and the helpers `And`, `Or`, `Not`, `Implies`
- arithmetic on parameters: `+ - * / %`, unary `+`/`-`
- literals: integers, floats, strings, booleans

Everything else is rejected: attribute access, subscripting, lambdas, comprehensions,
f-strings, walrus assignment, conditional expressions, starred and keyword arguments, calls
to anything but the four helpers, and any name beginning `__`. Policies are also bounded in
length, node count, and nesting depth.

This is a security boundary, not a convenience limit. Policy text comes from the
constitution; before this parser existed it was passed to `eval` behind an empty
`__builtins__`, which does not stop attribute traversal — `And.__globals__` reached a
populated builtins mapping, and a rule could execute arbitrary code. See
`docs/reviews/z3-lean-verification-audit.md`.

### Failure behavior — fail-closed

`Z3VerifyResult.status` records why an answer was produced. Only two values permit
execution:

| Status | Meaning | Effect |
|---|---|---|
| `PASS` | Solver ran, found no violation | allow |
| `FAIL` | Solver ran, found a violation | **block** |
| `INAPPLICABLE` | No policy names any parameter of this callable | **block** — exemptible |
| `UNAVAILABLE` | `z3-solver` not installed | **block** |
| `INVALID_POLICY` | Policy malformed, or names only some parameters | **block** |
| `UNKNOWN` | Solver timed out or returned unknown | **block** |
| `ERROR` | Verification raised | **block** |

`PASS` is the only status that allows. Use
`acgs_lite.z3_verify.blocks_execution(result)` rather than reading the fields. The rule is
an allowlist of exactly one member, so a status added later blocks until someone can say
what it *proves*.

Three consequences worth stating plainly:

- **A constitution with a `z3:` policy and no solver installed will block every governed
  call it applies to.** That is intended. Install `z3-solver`, or remove the policy — do
  not expect the layer to quietly skip. (A declared `z3` extra is pending: `pyproject.toml`
  is hash-sealed, so `pip install "acgs-lite[z3]"` does not work yet.)
- **A malformed policy raises at decoration time**, when `@GovernedCallable` is applied. For
  a module-scope decorator that means at import. A policy that cannot be parsed is a broken
  control, and the failure it replaces was exactly that such a policy used to be skipped
  with a `WARNING` while execution continued unchecked.
- **With no solver installed, an exemption does not help.** `UNAVAILABLE` is decided
  before applicability is, so a constitution carrying a `z3:` policy blocks every governed
  call under it — exempt or not. Exemptions cover "verification ran and had nothing to say
  about this callable", not "verification could not run". Install `z3-solver` or drop the
  policy; do not reach for an exemption to paper over a missing dependency.
- **`INAPPLICABLE` blocks, and it is the status you will meet first.** A constitution's
  policies are global while callables are many, so most callables under a `z3:` rule are
  named by none of it. Blocking them is deliberate: policy variables are built from type
  hints, so a callable with *no* annotations also binds nothing and looks equally
  inapplicable. The two are indistinguishable from inside the verifier, which means an
  ordinary refactor that drops a `: int` would otherwise move a callable outside its own
  control with no diagnostic. A gate that can be switched off by deleting an annotation is
  not a gate.

### Exemptions

To run a callable that verification cannot clear, say so explicitly:

```python
from acgs_lite import GovernedCallable, verification_exempt

@GovernedCallable(constitution)
@verification_exempt(
    reason="read-only key lookup; the financial policy set does not apply",
    approved_by="security@example.com",
    expires_at="2026-12-31T00:00:00+00:00",
    ticket="SEC-1421",
)
def rotate_key(name: str) -> str:
    ...
```

The requirements are deliberately awkward, because an exemption is a decision to execute
without verification:

- **explicit** — written at the callable. There is no glob, no config file, no global
  switch, and no way to exempt a set of functions at once.
- **attributed** — a non-empty reason and approver.
- **expiring** — a timezone-aware deadline, at most 365 days out. Naive, past, unparseable,
  and over-horizon deadlines are all refused at decoration time.

  Expiry has two distinct effects, and the operationally important one is the second.
  A process that is *already running* when the deadline passes starts blocking the call:
  `active_exemption` re-checks the deadline on every invocation. But a process that
  *starts* after the deadline does not get that far — `@verification_exempt` validates its
  arguments at decoration time, so a lapsed literal `expires_at` raises `ExemptionError`
  at import and **the service fails to boot**. That is the intended direction (a lapsed
  exemption must not be silently usable), but plan for it: a hardcoded date in a
  module-scope decorator is a scheduled outage unless someone renews it first. Treat the
  deadline as a calendar item, not a safety net.
- **audited** — every use writes a `verification_exemption` entry to the tamper-evident
  audit log *before* the call proceeds, marked `valid=False` with violation
  `Z3-VERIFICATION-INAPPLICABLE`. "Where did we execute unverified, and on whose authority"
  is a query over the audit chain.

Three limits on what an exemption can do:

- **It clears `INAPPLICABLE` and nothing else.** Not a proven violation, not a malformed
  policy, not a timeout, not a solver crash, not a missing solver. Verification runs first
  and its result is checked first; the exemption is consulted only afterwards.
- **Decorator order matters, and the wrong order denies.** `verification_exempt` must sit
  *below* `GovernedCallable` so it marks the function the gate holds. Above it, the mark
  lands on the wrapper, the gate never sees it, and the call blocks.
- **A hand-set attribute is not an exemption.** The gate type-checks the marker, so
  `func.__acgs_verification_exemption__ = True` does not grant anything.

### Limits

- **`float` is modelled as `z3.Real`**, an exact rational. A property proved over the
  rationals does not carry to IEEE-754: rounding, overflow, signed zero, and NaN are outside
  the model. `PASS` on a float parameter means "safe over the rationals".
- **A `None` argument leaves its variable free**, so the solver may find a violating
  assignment and block. Do not name an `Optional` parameter in a policy.
- **`Z3ConstraintVerifier.verify(action, context)`** — the action-*string* API — pins all six
  of its built-in principle variables before solving, so it evaluates a ground formula rather
  than searching. It is a keyword classifier with a solver attached; treat its result as a
  risk signal, not a proof.
- **`Z3VerificationGate`** (in `acgs_lite.formal.smt_gate`) asserts a disjunction of
  unconstrained booleans, so `satisfiable=True` and `contradiction=False` for every rule
  regardless of content — including a rule written to contradict itself. It is **not** wired
  to enforcement: no call is permitted or refused on its result. But it does back
  `acgs eval verify-constitution`, which prints those two fields per CRITICAL rule and exits
  non-zero only on `contradiction` — so that command always reports clean and always exits 0.
  **Do not read its name, or that command's exit code, as verification.**

## The Lean 4 layer

The trust boundary is the **Lean kernel**, not the language model. `LeanstralVerifier`
formalizes rules and generates a candidate proof with an LLM, then type-checks it.

The stages are reported separately:

| Field | Meaning |
|---|---|
| `proposed_theorem` | The theorem statement that was built |
| `proposed_proof` | The model's candidate proof text — unverified |
| `proved` | **True only if the Lean kernel accepted the proof** |
| `certificate` | Populated only for a kernel-verified proof |

With no Lean toolchain installed, verification returns `proved=False`, `certificate=None`,
and the candidate in `proposed_proof`. No `ProofCertificate` is minted for text no kernel
has read, and nothing reporting success reaches the audit trail on the strength of a
generated proof.

## What none of this claims

Neither layer makes acgs-lite compliance-certified, regulator-approved, or production-proven.
They check the properties you write, over the model of the code they can build from type
hints, using solvers whose limits are listed above. Everything outside that — the semantics
of the wrapped callable, the accuracy of the constitution, the behavior of anything not
named in a policy — is unverified.
