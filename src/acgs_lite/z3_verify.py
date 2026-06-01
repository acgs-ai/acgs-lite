"""Z3 constraint verifier — Layer 3 formal verification for high-risk actions.

Provides synchronous SMT-based verification of constitutional constraints
against agent actions. Designed for critical-risk actions (score >= 0.8)
where keyword matching and semantic scoring are insufficient.

Architecture position:
    Layer 1: GovernanceEngine (keyword rules, hot-path benchmarked per workload)
    Layer 2: ConstitutionalImpactScorer (semantic risk, model/backend dependent)
    Layer 3: Z3ConstraintVerifier (formal verification, solver/problem dependent, this module)

Usage::

    from acgs_lite.z3_verify import Z3ConstraintVerifier, Z3VerifyResult

    verifier = Z3ConstraintVerifier()
    result = verifier.verify("delete all production records", context={"env": "production"})
    if not result.satisfiable:
        print(f"Constraint violated: {result.counterexample}")
"""

from __future__ import annotations

import inspect
import logging
import time
import types
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Union, get_args, get_origin, get_type_hints

_log = logging.getLogger(__name__)

try:
    import z3

    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

try:
    from pydantic import BaseModel
    from pydantic.fields import FieldInfo

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = Any  # type: ignore
    FieldInfo = Any  # type: ignore

# Default timeout for Z3 solver (milliseconds)
_Z3_TIMEOUT_MS = 5_000

# Locked-down globals for evaluating policy expressions. eval() auto-injects the
# real builtins when given a globals dict without "__builtins__"; an empty mapping
# here blocks that, so a policy string sourced from a constitution rule cannot reach
# __import__/open/etc. Only the Z3 helpers + parsed variables (passed as locals) are
# in scope. SMT comparison expressions need no builtins, so this is non-restrictive
# for legitimate policies.
_POLICY_EVAL_GLOBALS: dict[str, Any] = {"__builtins__": {}}

# Risk threshold above which Z3 verification is recommended
Z3_RISK_THRESHOLD = 0.8


@dataclass(frozen=True, slots=True)
class Z3VerifyResult:
    """Result of Z3 formal verification."""

    satisfiable: bool
    """True if the action satisfies all constraints (no violation found)."""
    verified: bool
    """True if Z3 was actually invoked. False if Z3 unavailable or timed out."""
    solver_result: str
    """'sat', 'unsat', 'unknown', or 'skipped'."""
    counterexample: dict[str, Any] | None
    """Variable assignment that witnesses a violation, or None."""
    verification_time_ms: float
    error: str | None = None


# ---------------------------------------------------------------------------
# Built-in constitutional constraint builders
# ---------------------------------------------------------------------------


def _build_action_constraints(
    solver: Any,
    action: str,
    context: dict[str, Any] | None,
) -> None:
    """Add constitutional constraints to the solver for the given action.

    Constraints encode the six core ACGS principles as boolean variables:
      - data_destruction:   action destroys data
      - system_escalation:  action escalates privileges
      - production_write:   action writes to production
      - secret_exposure:    action exposes secrets
      - financial_mutation: action mutates financial records
      - auth_bypass:        action bypasses authentication

    A valid (constitutionally compliant) action must satisfy:
      NOT (data_destruction AND production_write)
      NOT secret_exposure
      NOT auth_bypass
      IF financial_mutation THEN NOT production_write (require staging)
    """
    action_lower = action.lower()
    ctx = context or {}

    # Boolean variables representing action characteristics
    data_destruction = z3.Bool("data_destruction")
    system_escalation = z3.Bool("system_escalation")
    production_write = z3.Bool("production_write")
    secret_exposure = z3.Bool("secret_exposure")
    financial_mutation = z3.Bool("financial_mutation")
    auth_bypass = z3.Bool("auth_bypass")

    # Derive variable values from action text and context
    _destruction_keywords = {"delete", "drop", "truncate", "destroy", "erase", "wipe", "rm -rf"}
    _escalation_keywords = {"sudo", "root", "admin", "chmod", "chown", "kernel", "privilege"}
    _secret_keywords = {"password", "secret", "token", "api_key", "credential", "private key"}
    _financial_keywords = {"payment", "transaction", "transfer", "billing", "invoice", "money"}
    _bypass_keywords = {"bypass", "skip auth", "override auth", "no-auth", "unauthenticated"}

    is_destruction = any(kw in action_lower for kw in _destruction_keywords)
    is_escalation = any(kw in action_lower for kw in _escalation_keywords)
    is_production = (
        any(kw in action_lower for kw in {"production", "prod ", " prod", "live"})
        or ctx.get("environment") == "production"
    )
    is_secret = any(kw in action_lower for kw in _secret_keywords)
    is_financial = any(kw in action_lower for kw in _financial_keywords)
    is_bypass = any(kw in action_lower for kw in _bypass_keywords)

    # Assert observed values
    solver.add(data_destruction == is_destruction)
    solver.add(system_escalation == is_escalation)
    solver.add(production_write == is_production)
    solver.add(secret_exposure == is_secret)
    solver.add(financial_mutation == is_financial)
    solver.add(auth_bypass == is_bypass)

    # Constitutional constraints (negated to find violations):
    # If any constraint is UNSAT, the action violates the constitution.
    # We assert the NEGATION of what is acceptable — if SAT, a violation exists.
    solver.add(
        z3.Or(
            z3.And(data_destruction, production_write),  # C1: no prod destruction
            secret_exposure,  # C2: no secret exposure
            auth_bypass,  # C3: no auth bypass
            z3.And(financial_mutation, production_write),  # C4: no direct prod finance writes
            z3.And(system_escalation, production_write),  # C5: no prod privilege escalation
        )
    )


def _extract_counterexample(model: Any) -> dict[str, Any]:
    """Extract a human-readable counterexample from a Z3 model."""
    result: dict[str, Any] = {}
    for decl in model.decls():
        val = model[decl]
        if z3.is_bool(val):
            result[decl.name()] = bool(val)
        elif z3.is_int(val):
            result[decl.name()] = int(val.as_long())
        elif z3.is_real(val):
            result[decl.name()] = float(val.as_fraction())
        elif hasattr(val, "as_string"):
            result[decl.name()] = val.as_string()
        else:
            result[decl.name()] = str(val)
    # Filter out False boolean variables only (keeping True booleans and numeric/string types)
    return {k: v for k, v in result.items() if v is not False}


# ---------------------------------------------------------------------------
# Verifier class
# ---------------------------------------------------------------------------


class Z3ConstraintVerifier:
    """Synchronous Z3-based constitutional constraint verifier.

    Intended for critical-risk actions where the cost of a false negative
    (allowing a harmful action) outweighs the verification latency.

    Falls back gracefully when z3-solver is not installed.
    """

    def __init__(self, timeout_ms: int = _Z3_TIMEOUT_MS) -> None:
        self._timeout_ms = timeout_ms
        if not Z3_AVAILABLE:
            _log.warning(
                "z3-solver not installed — Z3ConstraintVerifier will skip verification. "
                "Install with: pip install z3-solver"
            )

    @property
    def available(self) -> bool:
        """True if z3-solver is installed and usable."""
        return Z3_AVAILABLE

    def verify(
        self,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> Z3VerifyResult:
        """Formally verify an action against constitutional constraints.

        Returns Z3VerifyResult with:
          - satisfiable=True  → no violation found (action is safe per constraints)
          - satisfiable=False → violation detected; counterexample shows which constraints
          - verified=False    → Z3 unavailable or timed out; treat as inconclusive

        Args:
            action: The agent action string to verify.
            context: Optional dict with keys like "environment", "authenticated".
        """
        if not Z3_AVAILABLE:
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="skipped",
                counterexample=None,
                verification_time_ms=0.0,
                error="z3-solver not installed",
            )

        start = time.perf_counter()
        try:
            solver = z3.Solver()
            solver.set("timeout", self._timeout_ms)
            _build_action_constraints(solver, action, context)

            check_result = solver.check()
            elapsed_ms = (time.perf_counter() - start) * 1000

            if check_result == z3.sat:
                # A violation was found — extract the counterexample
                counterexample = _extract_counterexample(solver.model())
                return Z3VerifyResult(
                    satisfiable=False,
                    verified=True,
                    solver_result="sat",
                    counterexample=counterexample,
                    verification_time_ms=elapsed_ms,
                )
            elif check_result == z3.unsat:
                # No violation possible — constraints are unsatisfiable
                return Z3VerifyResult(
                    satisfiable=True,
                    verified=True,
                    solver_result="unsat",
                    counterexample=None,
                    verification_time_ms=elapsed_ms,
                )
            else:
                # unknown — solver timed out or gave up
                return Z3VerifyResult(
                    satisfiable=True,
                    verified=False,
                    solver_result="unknown",
                    counterexample=None,
                    verification_time_ms=elapsed_ms,
                    error="Z3 solver returned unknown (possible timeout)",
                )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            _log.warning("Z3 verification error: %s", type(exc).__name__)
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="unknown",
                counterexample=None,
                verification_time_ms=elapsed_ms,
                error=type(exc).__name__,
            )


# ---------------------------------------------------------------------------
# Pydantic & Type-Hint boundary parsers for SMT / Z3
# ---------------------------------------------------------------------------


def _unwrap_type(ann: Any) -> Any:
    """Recursively unwrap Optional, Union, and Annotated type wrappers."""
    if ann is None:
        return None
    origin = get_origin(ann)
    # Handle Union types (e.g. Union[int, None], int | None)
    if origin is Union or (hasattr(types, "UnionType") and isinstance(ann, types.UnionType)):
        args = get_args(ann)
        # Filter out NoneType (we want the actual base type)
        filtered_args = [arg for arg in args if arg is not type(None)]
        if len(filtered_args) == 1:
            return _unwrap_type(filtered_args[0])
    return ann


def _parse_type_and_constraints(
    name: str,
    annotation: Any,
    metadata: list[Any],
) -> tuple[Any | None, list[Any]]:
    """Determine Z3 variable type and extract constraints for a field/parameter."""
    unwrapped = annotation
    direct_metadata = list(metadata)

    # Handle Annotated[T, Metadata...]
    if get_origin(annotation) is not None and hasattr(annotation, "__metadata__"):
        args = get_args(annotation)
        unwrapped = args[0]
        for m in args[1:]:
            if hasattr(m, "metadata") and isinstance(m.metadata, list):
                direct_metadata.extend(m.metadata)
            else:
                direct_metadata.append(m)

    unwrapped = _unwrap_type(unwrapped)
    if unwrapped is None:
        return None, []

    # Map Python types to Z3 types
    try:
        if issubclass(unwrapped, bool):
            var = z3.Bool(name)
        elif issubclass(unwrapped, int):
            var = z3.Int(name)
        elif issubclass(unwrapped, float):
            var = z3.Real(name)
        elif issubclass(unwrapped, str):
            var = z3.String(name)
        else:
            return None, []
    except TypeError:
        return None, []

    constraints = []
    for m in direct_metadata:
        # Check if metadata is a tuple from Pydantic v1 FieldInfo attributes (e.g. ("gt", 0))
        if isinstance(m, tuple) and len(m) == 2:
            op, val = m
            if op == "gt":
                constraints.append(var > val)
            elif op == "ge":
                constraints.append(var >= val)
            elif op == "lt":
                constraints.append(var < val)
            elif op == "le":
                constraints.append(var <= val)
            elif op == "min_length":
                constraints.append(z3.Length(var) >= val)
            elif op == "max_length":
                constraints.append(z3.Length(var) <= val)
        else:
            # Check for standard annotated_types/Pydantic validation objects
            cls_name = type(m).__name__
            if cls_name == "Gt" or hasattr(m, "gt"):
                constraints.append(var > m.gt)
            elif cls_name == "Ge" or hasattr(m, "ge"):
                constraints.append(var >= m.ge)
            elif cls_name == "Lt" or hasattr(m, "lt"):
                constraints.append(var < m.lt)
            elif cls_name == "Le" or hasattr(m, "le"):
                constraints.append(var <= m.le)
            elif cls_name == "MinLen" or hasattr(m, "min_length"):
                constraints.append(z3.Length(var) >= m.min_length)
            elif cls_name == "MaxLen" or hasattr(m, "max_length"):
                constraints.append(z3.Length(var) <= m.max_length)

    return var, constraints


def parse_pydantic_to_z3(model_class: type[BaseModel]) -> tuple[dict[str, Any], list[Any]]:
    """Parse a Pydantic model into a dictionary of Z3 variables and validation constraints.

    Converts standard fields and numeric boundaries (gt, ge, lt, le) and string lengths
    (min_length, max_length) into Z3 constraints.

    Returns:
        tuple[variables_dict, constraints_list]:
            variables_dict: Maps field name (str) to Z3 variable.
            constraints_list: List of Z3 boolean expressions for the validation rules.
    """
    if not Z3_AVAILABLE:
        return {}, []
    if not PYDANTIC_AVAILABLE or not issubclass(model_class, BaseModel):
        return {}, []

    variables: dict[str, Any] = {}
    constraints: list[Any] = []

    # Handle Pydantic v2
    if hasattr(model_class, "model_fields"):
        for name, field in model_class.model_fields.items():
            ann = field.annotation
            var_type, var_constraints = _parse_type_and_constraints(name, ann, field.metadata)
            if var_type is not None:
                variables[name] = var_type
                constraints.extend(var_constraints)
    # Handle Pydantic v1
    elif hasattr(model_class, "__fields__"):
        for name, field in model_class.__fields__.items():  # type: ignore[attr-defined]
            ann = field.type_
            field_info = getattr(field, "field_info", None)
            metadata = []
            if field_info:
                for attr in ["gt", "ge", "lt", "le", "min_length", "max_length"]:
                    val = getattr(field_info, attr, None)
                    if val is not None:
                        metadata.append((attr, val))
            var_type, var_constraints = _parse_type_and_constraints(name, ann, metadata)
            if var_type is not None:
                variables[name] = var_type
                constraints.extend(var_constraints)

    return variables, constraints


def parse_callable_to_z3(func: Callable[..., Any]) -> tuple[dict[str, Any], list[Any]]:
    """Parse a function's type-hinted parameters and default value metadata into Z3 variables.

    Supports direct annotations, Annotated type wrappers, and Pydantic BaseModel parameters.
    """
    if not Z3_AVAILABLE:
        return {}, []

    variables: dict[str, Any] = {}
    constraints: list[Any] = []

    try:
        sig = inspect.signature(func)
    except (ValueError, TypeError):
        return {}, []

    try:
        fn_globals = getattr(func, "__globals__", None)
        hints = get_type_hints(func, globalns=fn_globals, include_extras=True)
    except Exception:
        hints = {}

    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue

        ann = hints.get(name, param.annotation)
        if ann is inspect.Parameter.empty:
            continue

        # Check if the parameter is a Pydantic model itself
        try:
            if PYDANTIC_AVAILABLE and inspect.isclass(ann) and issubclass(ann, BaseModel):
                sub_vars, sub_consts = parse_pydantic_to_z3(ann)
                variables.update(sub_vars)
                constraints.extend(sub_consts)
                continue
        except TypeError:
            pass

        # Otherwise, parse standard parameter annotations and defaults
        metadata = []
        default_val = param.default
        if PYDANTIC_AVAILABLE and isinstance(default_val, FieldInfo) and default_val.metadata:
            metadata.extend(default_val.metadata)

        var_type, var_constraints = _parse_type_and_constraints(name, ann, metadata)
        if var_type is not None:
            variables[name] = var_type
            constraints.extend(var_constraints)

    return variables, constraints


def verify_callable_safety(
    func: Callable[..., Any],
    policies: list[str | Any],
    timeout_ms: int = _Z3_TIMEOUT_MS,
) -> Z3VerifyResult:
    """Formally verify if a function's type-hint boundaries can violate any safety policies.

    Checks if there exists any assignment to the parameters that satisfies type-hint boundaries
    but violates (i.e. satisfies the negation of) any safety policy.

    Policies can be Z3 expressions or string expressions like "amount < 500" or
    "And(amount < 500, amount > 0)".
    """
    if not Z3_AVAILABLE:
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="skipped",
            counterexample=None,
            verification_time_ms=0.0,
            error="z3-solver not installed",
        )

    start = time.perf_counter()
    variables, constraints = parse_callable_to_z3(func)
    if not variables:
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="skipped",
            counterexample=None,
            verification_time_ms=0.0,
            error="No type-hinted variables found to verify",
        )

    try:
        # Build evaluation context
        eval_ctx = {
            **variables,
            "And": z3.And,
            "Or": z3.Or,
            "Not": z3.Not,
            "Implies": z3.Implies,
        }

        parsed_policies = []
        for policy in policies:
            if isinstance(policy, str):
                try:
                    expr = eval(policy, _POLICY_EVAL_GLOBALS, eval_ctx)  # noqa: S307 - sandboxed builtins
                    parsed_policies.append(expr)
                except Exception as e:
                    _log.warning("Failed to parse policy string '%s': %s", policy, e)
                    continue
            else:
                parsed_policies.append(policy)

        if not parsed_policies:
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="skipped",
                counterexample=None,
                verification_time_ms=0.0,
                error="No valid safety policies found",
            )

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)

        for c in constraints:
            solver.add(c)

        # Violation exists if any policy is false: Or(Not(p1), Not(p2), ...)
        solver.add(z3.Or(*[z3.Not(p) for p in parsed_policies]))

        check_result = solver.check()
        elapsed_ms = (time.perf_counter() - start) * 1000

        if check_result == z3.sat:
            counterexample = _extract_counterexample(solver.model())
            return Z3VerifyResult(
                satisfiable=False,
                verified=True,
                solver_result="sat",
                counterexample=counterexample,
                verification_time_ms=elapsed_ms,
            )
        elif check_result == z3.unsat:
            return Z3VerifyResult(
                satisfiable=True,
                verified=True,
                solver_result="unsat",
                counterexample=None,
                verification_time_ms=elapsed_ms,
            )
        else:
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="unknown",
                counterexample=None,
                verification_time_ms=elapsed_ms,
                error="Z3 solver returned unknown (possible timeout)",
            )

    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        _log.warning("Z3 safety verification error: %s", type(exc).__name__)
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="unknown",
            counterexample=None,
            verification_time_ms=elapsed_ms,
            error=type(exc).__name__,
        )


def verify_callable_arguments(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    policies: list[str | Any],
    timeout_ms: int = _Z3_TIMEOUT_MS,
) -> Z3VerifyResult:
    """Verify concrete runtime arguments of a function call against safety policies using Z3."""
    if not Z3_AVAILABLE:
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="skipped",
            counterexample=None,
            verification_time_ms=0.0,
            error="z3-solver not installed",
        )

    start = time.perf_counter()
    variables, constraints = parse_callable_to_z3(func)
    if not variables:
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="skipped",
            counterexample=None,
            verification_time_ms=0.0,
            error="No type-hinted variables found to verify",
        )

    try:
        # Map arguments to variable names
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()

        concrete_constraints = []
        for name, val in bound.arguments.items():
            if name in variables:
                var = variables[name]
                if PYDANTIC_AVAILABLE and isinstance(val, BaseModel):
                    if hasattr(val, "model_fields"):
                        for f_name in val.model_fields:
                            if f_name in variables:
                                f_val = getattr(val, f_name, None)
                                if f_val is not None:
                                    concrete_constraints.append(variables[f_name] == f_val)
                    elif hasattr(val, "__fields__"):
                        for f_name in val.__fields__:  # type: ignore[attr-defined]
                            if f_name in variables:
                                f_val = getattr(val, f_name, None)
                                if f_val is not None:
                                    concrete_constraints.append(variables[f_name] == f_val)
                else:
                    if val is not None:
                        concrete_constraints.append(var == val)

        eval_ctx = {
            **variables,
            "And": z3.And,
            "Or": z3.Or,
            "Not": z3.Not,
            "Implies": z3.Implies,
        }

        parsed_policies = []
        for policy in policies:
            if isinstance(policy, str):
                try:
                    expr = eval(policy, _POLICY_EVAL_GLOBALS, eval_ctx)  # noqa: S307 - sandboxed builtins
                    parsed_policies.append(expr)
                except Exception as e:
                    _log.warning("Failed to parse policy string '%s': %s", policy, e)
                    continue
            else:
                parsed_policies.append(policy)

        if not parsed_policies:
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="skipped",
                counterexample=None,
                verification_time_ms=0.0,
                error="No valid safety policies found",
            )

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)

        for c in constraints:
            solver.add(c)
        for c in concrete_constraints:
            solver.add(c)

        # Violation exists if any policy is false
        solver.add(z3.Or(*[z3.Not(p) for p in parsed_policies]))

        check_result = solver.check()
        elapsed_ms = (time.perf_counter() - start) * 1000

        if check_result == z3.sat:
            counterexample = _extract_counterexample(solver.model())
            return Z3VerifyResult(
                satisfiable=False,
                verified=True,
                solver_result="sat",
                counterexample=counterexample,
                verification_time_ms=elapsed_ms,
            )
        elif check_result == z3.unsat:
            return Z3VerifyResult(
                satisfiable=True,
                verified=True,
                solver_result="unsat",
                counterexample=None,
                verification_time_ms=elapsed_ms,
            )
        else:
            return Z3VerifyResult(
                satisfiable=True,
                verified=False,
                solver_result="unknown",
                counterexample=None,
                verification_time_ms=elapsed_ms,
                error="Z3 solver returned unknown (possible timeout)",
            )

    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        _log.warning("Z3 runtime argument verification error: %s", type(exc).__name__)
        return Z3VerifyResult(
            satisfiable=True,
            verified=False,
            solver_result="unknown",
            counterexample=None,
            verification_time_ms=elapsed_ms,
            error=type(exc).__name__,
        )


def _extract_z3_policies(constitution: Any) -> list[str]:
    """Helper to extract Z3 SMT policy strings from active constitution rules."""
    policies: list[str] = []
    if not constitution or not hasattr(constitution, "rules"):
        return policies
    for rule in constitution.rules:
        if not getattr(rule, "enabled", True) or getattr(rule, "deprecated", False):
            continue
        # Extract from rule metadata
        metadata = getattr(rule, "metadata", {}) or {}
        for key in ("z3_expression", "smt_constraint"):
            if key in metadata:
                val = metadata[key]
                if isinstance(val, str) and val:
                    policies.append(val)
        # Extract from rule text if prefixed with z3: or smt:
        text = getattr(rule, "text", "") or ""
        text_stripped = text.strip()
        if text_stripped.startswith("z3:") or text_stripped.startswith("smt:"):
            policies.append(text_stripped.split(":", 1)[1].strip())
    return policies
