"""Adversarial production-boundary regressions."""

from __future__ import annotations

import asyncio
import functools
import gc
import os
import stat
import threading
import weakref
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import pytest

from acgs_lite import ConstitutionalViolationError, GovernedAgent, MACIRole
from acgs_lite.audit import AuditEntry, AuditLog, JSONLAuditBackend
from acgs_lite.constitution import Constitution
from acgs_lite.formal.exemption import verification_exempt
from acgs_lite.governed import GovernedCallable, _enforce_z3_gate
from acgs_lite.legitimacy import (
    BASELINE_CONSTRAINT_MARKER,
    AuthorizationProfile,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
    TrustedExecutionContext,
)
from acgs_lite.legitimacy.invocation import (
    InvocationBinding,
    PolicyBinding,
    bind_invocation,
    bind_policy,
)
from acgs_lite.legitimacy.ledger import AttemptStatus, InProcessGrantLedger
from acgs_lite.z3_verify import VerificationStatus, Z3VerifyResult


def _guard(**kwargs: Any) -> GovernedCallable:
    return GovernedCallable(
        Constitution.default(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        **kwargs,
    )


def _trusted_context(
    *, scope: str = "tenant-a", subjects: frozenset[str] = frozenset({"account-1"})
) -> TrustedExecutionContext:
    return TrustedExecutionContext(
        actor_id="authenticated-host-actor",
        scope=scope,
        allowed_subjects=subjects,
    )


def test_trusted_context_signature_aliases_allow_once_and_bind_all_subjects() -> None:
    calls: list[str] = []
    guard = _guard(trusted_execution_context=_trusted_context())

    @guard
    def action(account_id: str, *, tenant_id: str = "tenant-a") -> str:
        calls.append(account_id)
        return account_id

    grant = action.issue_grant("account-1")
    assert action("account-1", execution_grant=grant, execution_attempt_id="aliases") == "account-1"
    assert action("account-1", execution_grant=grant, execution_attempt_id="aliases") == "account-1"
    with pytest.raises(LegitimacyInvariantError):
        action("account-2", execution_grant=grant)
    with pytest.raises(LegitimacyInvariantError):
        action("account-1", tenant_id="tenant-b", execution_grant=grant)
    assert calls == ["account-1"]


def test_trusted_context_cannot_hide_subject_alias_behind_explicit_subjects() -> None:
    calls: list[str] = []
    guard = _guard(trusted_execution_context=_trusted_context())

    @guard
    def action(scope: str, subjects: tuple[str, ...], account_id: str) -> str:
        calls.append(account_id)
        return account_id

    with pytest.raises(LegitimacyInvariantError, match="subjects"):
        action.issue_grant("tenant-a", ("account-1",), "untrusted-account")
    grant = action.issue_grant("tenant-a", ("account-1",), "account-1")
    assert action("tenant-a", ("account-1",), "account-1", execution_grant=grant) == "account-1"
    assert calls == ["account-1"]


def test_production_rejects_conflicting_scope_aliases() -> None:
    guard = _guard(trusted_execution_context=_trusted_context())

    @guard
    def action(scope: str, tenant_id: str, subjects: tuple[str, ...]) -> str:
        return "safe"

    with pytest.raises(LegitimacyInvariantError, match="scope"):
        action.issue_grant("tenant-a", "tenant-b", ("account-1",))

    grant = action.issue_grant("tenant-a", "tenant-a", ("account-1",))
    assert action("tenant-a", "tenant-a", ("account-1",), execution_grant=grant) == "safe"


@pytest.mark.parametrize(
    "scope_name",
    ["tenant", "workspace_id", "organization_id", "org_id", "project_id", "governance_scope"],
)
@pytest.mark.parametrize(
    "subject_name",
    [
        "subject",
        "subject_id",
        "resource",
        "resource_id",
        "object_id",
        "customer_id",
        "user_id",
        "governance_subjects",
    ],
)
def test_production_identity_aliases_in_bound_kwargs(scope_name: str, subject_name: str) -> None:
    guard = _guard(trusted_execution_context=_trusted_context())

    @guard
    def action(**identity: Any) -> str:
        return "safe"

    arguments = {scope_name: "tenant-a", subject_name: "account-1", "account_id": "account-1"}
    grant = action.issue_grant(**arguments)
    assert action(**arguments, execution_grant=grant) == "safe"
    with pytest.raises(LegitimacyInvariantError, match="subjects"):
        action.issue_grant(**{**arguments, "account_id": "untrusted-account"})


def test_production_positional_only_scope_cannot_be_shadowed_by_kwargs() -> None:
    guard = _guard(trusted_execution_context=_trusted_context())

    @guard
    def action(scope: str, /, **identity: Any) -> str:
        return "safe"

    with pytest.raises(LegitimacyInvariantError, match="scope"):
        action.issue_grant("tenant-b", scope="tenant-a", account_id="account-1")


def test_variadic_keyword_container_name_is_not_identity_metadata() -> None:
    guard = _guard(trusted_execution_context=_trusted_context())

    def by_scope(**scope: Any) -> str:
        return str(scope["account_id"])

    def by_subjects(**subjects: Any) -> str:
        return str(subjects["account_id"])

    for function in [by_scope, by_subjects]:
        action = guard(function)
        grant = action.issue_grant(tenant_id="tenant-a", account_id="account-1")
        assert (
            action(tenant_id="tenant-a", account_id="account-1", execution_grant=grant)
            == "account-1"
        )


def test_compatibility_binding_keeps_historical_explicit_metadata() -> None:
    def action(scope: str, subjects: tuple[str, ...], account_id: str) -> str:
        return account_id

    bound = bind_invocation(action, ("tenant-a", ("account-1",), "account-2"), {})
    assert bound.scope == "tenant-a"
    assert bound.subjects == ("account-1",)


def test_terminal_audit_and_unknown_mark_failure_disable_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    audit = AuditLog(backend=_FailSecondFlushBackend(tmp_path / "unconfirmed.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)

    def fail_unknown(**kwargs: Any) -> Any:
        raise OSError("cannot mark unknown")

    monkeypatch.setattr(guard._ledger, "mark_unknown", fail_unknown)
    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        charge(10, execution_grant=grant, execution_attempt_id="unconfirmed")
    with pytest.raises(LegitimacyInvariantError, match="disabled"):
        charge(10, execution_grant=grant, execution_attempt_id="unconfirmed")
    with pytest.raises(LegitimacyInvariantError, match="disabled"):
        charge.issue_grant(20)
    assert calls == [10]


@pytest.mark.parametrize("after_commit", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_durable_completion_absent_on_terminal_ledger_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_commit: bool, asynchronous: bool
) -> None:
    calls: list[int] = []
    path = tmp_path / "terminal.jsonl"
    audit = AuditLog(backend=JSONLAuditBackend(path))
    guard = _guard(audit_log=audit, require_durable_audit=True)

    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    async def async_charge(amount: int) -> str:
        return charge(amount)

    target = guard(async_charge if asynchronous else charge)
    grant = target.issue_grant(10)
    original = guard._ledger.finalize

    def fail_terminal(**kwargs: Any) -> Any:
        if kwargs["status"] is AttemptStatus.COMPLETED:
            if after_commit:
                original(**kwargs)
            raise OSError("terminal ledger unavailable")
        return original(**kwargs)

    monkeypatch.setattr(guard._ledger, "finalize", fail_terminal)
    for message in ["result is unknown", "already partial"]:
        with pytest.raises(LegitimacyInvariantError, match=message):
            result = target(10, execution_grant=grant, execution_attempt_id="terminal")
            if asynchronous:
                asyncio.run(result)
    restored = AuditLog.from_backend(JSONLAuditBackend(path))
    assert restored.verify_chain()
    assert not any(row.type == "execution_completed" for row in restored.entries)
    assert calls == [10]


@pytest.mark.parametrize("fail_confirmation", [False, True])
def test_recovery_waits_for_durable_completion_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_confirmation: bool
) -> None:
    entered = threading.Event()
    release = threading.Event()
    replay_entered = threading.Event()
    calls: list[int] = []
    outcomes: list[Any] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "concurrent.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)
    original = audit.record_durable

    def hold_confirmation(entry: AuditEntry) -> Any:
        if entry.type == "execution_completed":
            entered.set()
            assert release.wait(10), "test release signal missing"
            if fail_confirmation:
                raise OSError("confirmation unavailable")
        return original(entry)

    monkeypatch.setattr(audit, "record_durable", hold_confirmation)

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)

    def invoke(*, replay: bool = False) -> None:
        if replay:
            replay_entered.set()
        try:
            outcomes.append(charge(10, execution_grant=grant, execution_attempt_id="same"))
        except Exception as exc:
            outcomes.append(exc)

    first = threading.Thread(target=invoke)
    second = threading.Thread(target=lambda: invoke(replay=True))
    first.start()
    try:
        assert entered.wait(10)
        second.start()
        assert replay_entered.wait(10)
        # An explicit lock observation proves exclusion without timing sleeps.
        assert guard._completion_lock.locked()
        assert not guard._completion_lock.acquire(blocking=False)
        assert outcomes == []
    finally:
        release.set()
        first.join(10)
        if second.ident is not None:
            second.join(10)
    assert not first.is_alive() and not second.is_alive()
    assert calls == [10]
    if fail_confirmation:
        assert len(outcomes) == 2
        assert all(isinstance(value, LegitimacyInvariantError) for value in outcomes)
        assert guard._ledger._attempts["same"].status is AttemptStatus.PARTIAL
    else:
        assert outcomes == ["charged", "charged"]


def test_required_trusted_context_missing_fails_closed() -> None:
    with pytest.raises(LegitimacyInvariantError, match="trusted execution context"):
        _guard(require_trusted_context=True)


@pytest.mark.parametrize(
    "option",
    [
        "trusted_context",
        "required_context",
        "durable_audit",
    ],
)
def test_high_assurance_options_reject_compatibility_profile(option: str, tmp_path: Path) -> None:
    options: dict[str, Any]
    if option == "trusted_context":
        options = {"trusted_execution_context": _trusted_context()}
    elif option == "required_context":
        options = {
            "require_trusted_context": True,
            "trusted_execution_context": _trusted_context(),
        }
    else:
        options = {
            "require_durable_audit": True,
            "audit_log": AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl")),
        }
    with pytest.raises(LegitimacyInvariantError, match="production"):
        GovernedCallable(Constitution.default(), **options)


def test_trusted_context_rejects_empty_actor_scope_and_subjects() -> None:
    with pytest.raises(LegitimacyInvariantError, match="actor_id"):
        TrustedExecutionContext("", "tenant-a", frozenset({"account-1"}))
    with pytest.raises(LegitimacyInvariantError, match="scope"):
        TrustedExecutionContext("actor", "", frozenset({"account-1"}))
    with pytest.raises(LegitimacyInvariantError, match="allowed_subjects"):
        TrustedExecutionContext("actor", "tenant-a", frozenset())


@pytest.mark.parametrize(
    ("scope", "subjects", "message"),
    [
        ("tenant-b", ("account-1",), "scope"),
        ("tenant-a", ("account-2",), "subjects"),
    ],
)
def test_trusted_context_mismatch_denies_without_side_effect(
    scope: str, subjects: tuple[str, ...], message: str
) -> None:
    calls: list[str] = []
    guard = _guard(
        trusted_execution_context=_trusted_context(),
        require_trusted_context=True,
    )

    @guard
    def lookup(value: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(value)
        return value

    with pytest.raises(LegitimacyInvariantError, match=message):
        lookup.issue_grant("safe", scope=scope, subjects=subjects)
    assert calls == []


def test_trusted_context_snapshot_change_rejects_grant_without_side_effect() -> None:
    calls: list[str] = []
    guard = _guard(
        trusted_execution_context=_trusted_context(),
        require_trusted_context=True,
    )

    @guard
    def lookup(value: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(value)
        return value

    grant = lookup.issue_grant("safe", scope="tenant-a", subjects=("account-1",))
    guard.trusted_execution_context = _trusted_context(scope="tenant-b")
    with pytest.raises(LegitimacyInvariantError, match="context"):
        lookup(
            "safe",
            scope="tenant-a",
            subjects=("account-1",),
            execution_grant=grant,
        )
    assert calls == []


def test_trusted_context_authorized_call_executes_once_and_recovers() -> None:
    calls: list[str] = []
    guard = _guard(
        trusted_execution_context=_trusted_context(),
        require_trusted_context=True,
    )

    @guard
    def lookup(value: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        calls.append(value)
        return value

    grant = lookup.issue_grant("safe", scope="tenant-a", subjects=("account-1",))
    kwargs = {
        "scope": "tenant-a",
        "subjects": ("account-1",),
        "execution_grant": grant,
        "execution_attempt_id": "trusted-context",
    }
    assert lookup("safe", **kwargs) == "safe"
    assert lookup("safe", **kwargs) == "safe"
    assert calls == ["safe"]


def test_execution_attempt_record_exposes_trusted_context_binding() -> None:
    ledger = InProcessGrantLedger()
    decision = ledger.consume(
        grant_id="grant-1",
        attempt_id="attempt-1",
        receipt_hash="receipt-1",
        invocation=InvocationBinding("module:call", "args", "tenant-a", ("account-1",)),
        policy=PolicyBinding("v1", "sha256", "policy"),
        context_digest="context-digest",
    )
    assert decision.record.context_digest == "context-digest"


def test_attempt_id_cannot_alias_distinct_grants() -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    first = charge.issue_grant(10)
    second = charge.issue_grant(10)
    assert charge(10, execution_grant=first, execution_attempt_id="shared") == "charged"

    with pytest.raises(LegitimacyInvariantError, match="attempt id"):
        charge(10, execution_grant=second, execution_attempt_id="shared")
    assert calls == [10]


def test_same_module_qualname_does_not_alias_distinct_callables() -> None:
    calls: list[str] = []
    guard = _guard()

    def left(amount: int) -> str:
        calls.append("left")
        return str(amount)

    def right(amount: int) -> str:
        calls.append("right")
        return str(amount)

    left.__qualname__ = right.__qualname__ = "collision"
    protected_left = guard(left)
    protected_right = guard(right)
    grant = protected_left.issue_grant(10)

    with pytest.raises(LegitimacyInvariantError, match="callable identity"):
        protected_right(10, execution_grant=grant)
    assert calls == []


def test_wrapped_target_executes_once_without_authorizing_underlying_callable() -> None:
    calls: list[str] = []
    guard = _guard()

    def original(value: int) -> int:
        calls.append("original")
        return value

    @functools.wraps(original)
    def wrapped(value: int) -> int:
        calls.append("wrapper")
        return original(value)

    protected = guard(wrapped)
    underlying = guard(original)
    grant = guard.issue_grant(protected, 1)
    with pytest.raises(LegitimacyInvariantError, match="callable identity"):
        underlying(1, execution_grant=grant)
    assert calls == []
    assert protected(1, execution_grant=grant, execution_attempt_id="wrapped") == 1
    assert protected(1, execution_grant=grant, execution_attempt_id="wrapped") == 1
    assert calls == ["wrapper", "original"]


@pytest.mark.parametrize("name", ["self", "cls"])
@pytest.mark.parametrize("keyword_only", [False, True])
def test_production_binds_ordinary_receiver_named_parameters(name: str, keyword_only: bool) -> None:
    calls: list[int] = []
    namespace: dict[str, Any] = {"calls": calls}
    signature = f"value, *, {name}" if keyword_only else name
    exec(f"def operation({signature}):\n    calls.append({name})\n    return {name}\n", namespace)
    protected = _guard()(namespace["operation"])
    args = (0,) if keyword_only else ()
    grant = protected.issue_grant(*args, **{name: 2})
    with pytest.raises(LegitimacyInvariantError, match="invocation binding mismatch"):
        protected(*args, **{name: 99}, execution_grant=grant)
    assert calls == []
    assert protected(*args, **{name: 2}, execution_grant=grant) == 2
    assert calls == [2]


def test_grant_target_is_authenticated_and_not_retained_by_issuer() -> None:
    guard = _guard()

    def original(value: int) -> int:
        return value

    def alternate(value: int) -> int:
        return value

    alternate.__qualname__ = original.__qualname__
    protected = guard(original)
    grant = protected.issue_grant(1)
    forged = replace(grant, callable_target=alternate)
    with pytest.raises(LegitimacyInvariantError, match="authenticity"):
        guard(alternate)(1, execution_grant=forged)
    target_ref = weakref.ref(original)
    del original, protected, forged
    gc.collect()
    assert target_ref() is not None  # An authentic grant keeps its exact target alive.
    del grant
    gc.collect()
    assert target_ref() is None  # The issuer does not retain abandoned grants.


def test_authentic_grant_without_exact_target_is_not_production_authority() -> None:
    guard = _guard()
    calls: list[int] = []

    def operation(value: int) -> int:
        calls.append(value)
        return value

    protected = guard(operation)
    normal = protected.issue_grant(1)
    unbound = guard._authority.issue(
        receipt=normal.receipt,
        invocation=bind_invocation(operation, (1,), {}, include_receiver=True),
        policy=bind_policy(guard.constitution),
    )
    with pytest.raises(LegitimacyInvariantError, match="callable identity"):
        protected(1, execution_grant=unbound)
    assert calls == []


def test_nested_own_wrapper_issuer_binds_the_immediate_execution_target() -> None:
    guard = _guard()
    calls: list[int] = []

    def operation(value: int) -> int:
        calls.append(value)
        return value

    inner = guard(operation)
    outer = guard(inner)
    grant = outer.issue_grant(1)
    assert grant.callable_target is inner
    with pytest.raises(LegitimacyInvariantError, match="callable identity"):
        inner(1, execution_grant=grant)
    assert calls == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_opaque_result_never_records_completion(tmp_path: Path, asynchronous: bool) -> None:
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "opaque.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)
    calls: list[str] = []

    def operation() -> object:
        calls.append("called")
        return object()

    async def async_operation() -> object:
        return operation()

    protected = guard(async_operation if asynchronous else operation)
    grant = protected.issue_grant()
    kwargs = {"execution_grant": grant, "execution_attempt_id": "opaque"}
    with pytest.raises(LegitimacyInvariantError, match="unknown"):
        if asynchronous:
            asyncio.run(protected(**kwargs))
        else:
            protected(**kwargs)
    assert calls == ["called"]
    assert guard._ledger._attempts["opaque"].status is AttemptStatus.PARTIAL
    assert not any(entry.type == "execution_completed" for entry in audit.entries)
    with pytest.raises(LegitimacyInvariantError, match="partial"):
        if asynchronous:
            asyncio.run(protected(**kwargs))
        else:
            protected(**kwargs)
    assert calls == ["called"]


def test_production_grant_refuses_unbound_receiver_methods() -> None:
    guard = _guard()

    class Account:
        @guard
        def charge(self, amount: int) -> str:
            return str(amount)

    # The attached issuer has no receiver; complete argument binding rejects it.
    with pytest.raises(LegitimacyInvariantError, match="arguments do not match"):
        Account().charge.issue_grant(10)


@pytest.mark.parametrize("keyword_receiver", [False, True])
def test_production_rejects_actual_inherited_receiver_even_if_digestible(
    keyword_receiver: bool,
) -> None:
    guard = _guard()
    calls: list[int] = []

    class Account(dict):
        @guard
        def charge(receiver, amount: int) -> str:
            calls.append(amount)
            return "charged"

    class Child(Account):
        pass

    account = Child()
    args = () if keyword_receiver else (account, 10)
    kwargs = {"receiver": account, "amount": 10} if keyword_receiver else {}
    with pytest.raises(LegitimacyInvariantError, match="receiver methods"):
        Account.charge.issue_grant(*args, **kwargs)
    assert calls == []


def test_production_rejects_bound_receiver_but_accepts_staticmethod() -> None:
    guard = _guard()

    class Account:
        def charge(receiver, amount: int) -> int:
            return amount

        @staticmethod
        @guard
        def read(self: int) -> int:
            return self

    with pytest.raises(LegitimacyInvariantError, match="receiver methods"):
        guard.issue_grant(Account().charge, 10)
    grant = Account.read.issue_grant(10)
    assert Account.read(10, execution_grant=grant) == 10


def test_production_rejects_classmethod_receiver() -> None:
    guard = _guard()

    class Account:
        @classmethod
        @guard
        def read(owner, amount: int) -> int:
            return amount

    with pytest.raises(LegitimacyInvariantError, match="receiver methods"):
        Account.read.issue_grant(Account, 10)


def test_free_function_name_can_match_builtin_descriptor() -> None:
    @_guard()
    def __str__(value: int) -> str:
        return str(value)

    grant = __str__.issue_grant(1)
    assert __str__(1, execution_grant=grant) == "1"


def test_variadic_receiver_cannot_cross_instances() -> None:
    guard = _guard()
    calls: list[object] = []

    class Account(dict):
        @guard
        def charge(*args) -> str:
            calls.append(args[0])
            return "charged"

    first, second = Account(), Account()
    with pytest.raises(LegitimacyInvariantError, match="receiver methods"):
        grant = Account.charge.issue_grant(first, 1)
        second.charge(1, execution_grant=grant)
    assert calls == []

    @guard
    def collect(*args: int) -> tuple[int, ...]:
        return args

    grant = collect.issue_grant(1, 2)
    assert collect(1, 2, execution_grant=grant) == (1, 2)


def test_aliased_method_cannot_cross_instances() -> None:
    guard = _guard()
    calls: list[object] = []

    def implementation(receiver: object, amount: int) -> str:
        calls.append(receiver)
        return str(amount)

    class Account(dict):
        charge = guard(implementation)

    first, second = Account(), Account()
    with pytest.raises(LegitimacyInvariantError, match="receiver methods"):
        grant = Account.charge.issue_grant(first, 1)
        second.charge(1, execution_grant=grant)
    assert calls == []


def test_missing_required_argument_is_rejected_during_grant_issuance() -> None:
    guard = _guard()

    @guard
    def transfer(account: str, amount: int) -> str:
        return f"{account}:{amount}"

    with pytest.raises(LegitimacyInvariantError, match="arguments do not match"):
        transfer.issue_grant("acct-1")


def test_distinct_enum_types_cannot_substitute_for_granted_argument() -> None:
    trusted_mode = Enum("Mode", {"READ": "read"}, module="trusted_a")
    untrusted_mode = Enum("Mode", {"READ": "read"}, module="untrusted_b")
    calls: list[object] = []
    guard = _guard()

    @guard
    def execute(mode: object) -> str:
        calls.append(mode)
        return "ok"

    grant = execute.issue_grant(trusted_mode.READ)
    with pytest.raises(LegitimacyInvariantError, match="invocation binding mismatch"):
        execute(untrusted_mode.READ, execution_grant=grant)
    assert calls == []


def test_default_scope_and_subjects_bind_on_issue_and_execution() -> None:
    calls: list[str] = []
    guard = _guard()

    @guard
    def lookup(
        value: str,
        *,
        scope: str = "tenant-a",
        subjects: tuple[str, ...] = ("account-1",),
    ) -> str:
        calls.append(value)
        return value

    grant = lookup.issue_grant("safe")
    assert lookup("safe", execution_grant=grant) == "safe"
    assert calls == ["safe"]


def test_unsupported_durable_execution_and_restart_recovery_fail_at_construction() -> None:
    with pytest.raises(LegitimacyInvariantError, match="durable execution ledger"):
        _guard(require_durable_execution=True)
    with pytest.raises(LegitimacyInvariantError, match="restart recovery"):
        _guard(require_restart_recovery=True)


def test_required_durable_audit_is_confirmed_before_side_effect(tmp_path: Path) -> None:
    calls: list[int] = []
    audit = AuditLog(backend=JSONLAuditBackend(tmp_path / "audit.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)
    assert charge(10, execution_grant=grant, execution_attempt_id="durable-1") == "charged"
    assert calls == [10]
    assert any(entry.type == "execution_authorized" for entry in audit.entries)


@pytest.mark.parametrize("fault", ["unrecovered", "replaced", "directory_fsync"])
def test_strict_audit_faults_block_tool_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    path = tmp_path / "audit.jsonl"
    backend = JSONLAuditBackend(path)
    if fault == "unrecovered":
        AuditLog(backend=backend).record_durable(AuditEntry("prior", "validation"))
    audit = AuditLog(backend=backend)
    guard = _guard(audit_log=audit, require_durable_audit=True)
    calls: list[int] = []

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    if fault == "unrecovered":
        before = path.read_bytes()
        with pytest.raises(RuntimeError, match="recover"):
            charge.issue_grant(10)
        assert calls == [] and path.read_bytes() == before
        return
    grant = charge.issue_grant(10)
    if fault == "replaced":
        path.rename(tmp_path / "prior.jsonl")
        path.write_bytes(b"")
    if fault == "directory_fsync":
        real_fsync = os.fsync

        def fail_directory(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory fsync failed")
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", fail_directory)
    with pytest.raises((RuntimeError, OSError, LegitimacyInvariantError)):
        charge(10, execution_grant=grant, execution_attempt_id="blocked")
    assert calls == []
    if fault == "directory_fsync":
        monkeypatch.setattr(os, "fsync", real_fsync)
        fresh_grant = charge.issue_grant(10)
        assert charge(10, execution_grant=fresh_grant, execution_attempt_id="fresh") == "charged"
        assert calls == [10]


def test_side_effectful_agent_rejects_output_retry_configuration() -> None:
    with pytest.raises(ValueError, match="side-effectful"):
        GovernedAgent(
            lambda value: value,
            maci_role=MACIRole.EXECUTOR,
            side_effectful=True,
            max_retries=1,
        )


@pytest.mark.asyncio
async def test_cancelled_attempt_is_terminal_and_not_reexecuted() -> None:
    calls: list[int] = []
    started = asyncio.Event()
    release = asyncio.Event()
    guard = _guard()

    @guard
    async def charge(amount: int) -> str:
        calls.append(amount)
        started.set()
        await release.wait()
        return "charged"

    grant = charge.issue_grant(10)
    task = asyncio.create_task(
        charge(10, execution_grant=grant, execution_attempt_id="cancelled-1")
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    with pytest.raises(LegitimacyInvariantError, match="already cancelled"):
        await charge(10, execution_grant=grant, execution_attempt_id="cancelled-1")
    assert calls == [10]


def test_terminal_commit_failure_is_partial_and_never_reports_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)
    original_finalize = guard._ledger.finalize
    failed_once = False

    def fail_completed_once(**kwargs: Any) -> Any:
        nonlocal failed_once
        if kwargs["status"].value == "completed" and not failed_once:
            failed_once = True
            original_finalize(**kwargs)
            raise OSError("terminal store unavailable")
        return original_finalize(**kwargs)

    monkeypatch.setattr(guard._ledger, "finalize", fail_completed_once)
    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        charge(10, execution_grant=grant, execution_attempt_id="partial-1")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        charge(10, execution_grant=grant, execution_attempt_id="partial-1")
    assert calls == [10]


def test_output_rejection_after_call_is_partial_and_not_reexecuted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "forbidden output"

    grant = charge.issue_grant(10)
    original_validate = guard.engine.validate

    def reject_output(payload: Any, **kwargs: Any) -> Any:
        if str(kwargs.get("agent_id", "")).endswith(":output"):
            raise ConstitutionalViolationError("output rejected", rule_id="TEST-OUTPUT")
        return original_validate(payload, **kwargs)

    monkeypatch.setattr(guard.engine, "validate", reject_output)
    with pytest.raises(ConstitutionalViolationError, match="output rejected"):
        charge(10, execution_grant=grant, execution_attempt_id="output-partial")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        charge(10, execution_grant=grant, execution_attempt_id="output-partial")
    assert calls == [10]


class _FailSecondFlushBackend(JSONLAuditBackend):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        if self.flush_count == 2:
            raise OSError("terminal audit unavailable")
        super().flush()


def test_required_terminal_audit_failure_exposes_unknown_without_replay(tmp_path: Path) -> None:
    calls: list[int] = []
    audit = AuditLog(backend=_FailSecondFlushBackend(tmp_path / "audit.jsonl"))
    guard = _guard(audit_log=audit, require_durable_audit=True)

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)
    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        charge(10, execution_grant=grant, execution_attempt_id="terminal-audit")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        charge(10, execution_grant=grant, execution_attempt_id="terminal-audit")
    assert calls == [10]


def test_required_durable_audit_covers_z3_exemption_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _FailSecondFlushBackend(tmp_path / "exemption.jsonl")
    backend.flush_count = 1
    audit = AuditLog(backend=backend)

    @verification_exempt(
        reason="policy does not apply",
        approved_by="security@example.com",
        expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        ticket="TEST-1",
    )
    def lookup(name: str) -> str:
        return name

    result = Z3VerifyResult(
        satisfiable=False,
        verified=True,
        solver_result="skipped",
        counterexample=None,
        verification_time_ms=0.0,
        status=VerificationStatus.INAPPLICABLE,
    )
    monkeypatch.setattr("acgs_lite.z3_verify.verify_callable_arguments", lambda *_a, **_k: result)

    with pytest.raises(OSError, match="terminal audit unavailable"):
        _enforce_z3_gate(
            lookup,
            ("key",),
            {},
            ["amount < 500"],
            audit_log=audit,
            agent_id="test",
            require_durable_audit=True,
        )
    assert audit.entries == []


def test_mutated_completed_result_is_not_recovered_as_success() -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    def collect(value: int) -> list[str]:
        calls.append(value)
        return ["original"]

    grant = collect.issue_grant(1)
    first = collect(1, execution_grant=grant, execution_attempt_id="mutable-result")
    first.append("caller-mutated")

    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        collect(1, execution_grant=grant, execution_attempt_id="mutable-result")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        collect(1, execution_grant=grant, execution_attempt_id="mutable-result")
    assert calls == [1]


def test_custom_result_with_constant_repr_is_not_recovered_as_verified() -> None:
    class MutableOpaque:
        def __init__(self) -> None:
            self.state = "original"

        def __repr__(self) -> str:
            return "<opaque>"

    calls: list[int] = []
    guard = _guard()

    @guard
    def collect(value: int) -> MutableOpaque:
        calls.append(value)
        return MutableOpaque()

    grant = collect.issue_grant(1)
    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        collect(1, execution_grant=grant, execution_attempt_id="opaque-result")
    assert guard._ledger._attempts["opaque-result"].status is AttemptStatus.PARTIAL
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        collect(1, execution_grant=grant, execution_attempt_id="opaque-result")
    assert calls == [1]


def test_policy_content_change_after_grant_denies_before_call() -> None:
    calls: list[str] = []
    guard = _guard()

    @guard
    def execute(value: str) -> str:
        calls.append(value)
        return value

    grant = execute.issue_grant("safe")
    guard.constitution = Constitution(name="changed-policy", version="changed", rules=[])
    with pytest.raises(LegitimacyInvariantError, match="policy binding mismatch"):
        execute("safe", execution_grant=grant)
    assert calls == []


@pytest.mark.parametrize("decision_type", ["ALLOW_WITH_CONTROLS", "TRANSFORM_REQUIRED"])
def test_production_rejects_untrusted_controlled_or_transform_carrier(
    decision_type: str,
) -> None:
    calls: list[str] = []
    guard = _guard()

    @guard
    def execute(value: str) -> str:
        calls.append(value)
        return value

    receipt = DecisionReceipt.create(
        request_id="external",
        goal="execute",
        proposed_method="execute",
        decision_type=decision_type,
        authority_basis="caller-controlled",
        matched_constraints=(BASELINE_CONSTRAINT_MARKER,),
        policy_version=Constitution.default().hash,
        required_controls=("MFA",) if decision_type == "ALLOW_WITH_CONTROLS" else (),
        execution_boundary=ExecutionBoundary(
            allowed_method="execute",
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=True,
        ),
    )
    with pytest.raises(LegitimacyInvariantError, match="unsigned receipt"):
        execute("safe", decision_receipt=receipt)
    assert calls == []


def test_changed_actual_call_requires_fresh_grant() -> None:
    calls: list[str] = []
    guard = _guard()

    @guard
    def execute(value: str) -> str:
        calls.append(value)
        return value

    original = execute.issue_grant("original")
    with pytest.raises(LegitimacyInvariantError, match="invocation binding mismatch"):
        execute("transformed", execution_grant=original)
    fresh = execute.issue_grant("transformed")
    assert execute("transformed", execution_grant=fresh) == "transformed"
    assert calls == ["transformed"]


class _FailFirstFlushBackend(JSONLAuditBackend):
    def flush(self) -> None:
        raise OSError("preauthorization audit unavailable")


def test_required_initial_audit_failure_denies_before_call(tmp_path: Path) -> None:
    calls: list[int] = []
    guard = _guard(
        audit_log=AuditLog(backend=_FailFirstFlushBackend(tmp_path / "audit.jsonl")),
        require_durable_audit=True,
    )

    @guard
    def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)
    with pytest.raises(OSError, match="preauthorization audit unavailable"):
        charge(10, execution_grant=grant, execution_attempt_id="preauth-fail")
    assert calls == []


@pytest.mark.asyncio
async def test_async_output_rejection_is_partial_without_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    async def charge(amount: int) -> str:
        calls.append(amount)
        return "forbidden output"

    grant = charge.issue_grant(10)
    original_validate = guard.engine.validate

    def reject_output(payload: Any, **kwargs: Any) -> Any:
        if str(kwargs.get("agent_id", "")).endswith(":output"):
            raise ConstitutionalViolationError("output rejected", rule_id="TEST-OUTPUT")
        return original_validate(payload, **kwargs)

    monkeypatch.setattr(guard.engine, "validate", reject_output)
    with pytest.raises(ConstitutionalViolationError, match="output rejected"):
        await charge(10, execution_grant=grant, execution_attempt_id="async-output")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        await charge(10, execution_grant=grant, execution_attempt_id="async-output")
    assert calls == [10]


@pytest.mark.asyncio
async def test_async_terminal_commit_failure_is_unknown_without_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    guard = _guard()

    @guard
    async def charge(amount: int) -> str:
        calls.append(amount)
        return "charged"

    grant = charge.issue_grant(10)
    original_finalize = guard._ledger.finalize
    failed_once = False

    def fail_completed_once(**kwargs: Any) -> Any:
        nonlocal failed_once
        if kwargs["status"].value == "completed" and not failed_once:
            failed_once = True
            original_finalize(**kwargs)
            raise OSError("terminal store unavailable")
        return original_finalize(**kwargs)

    monkeypatch.setattr(guard._ledger, "finalize", fail_completed_once)
    with pytest.raises(LegitimacyInvariantError, match="result is unknown"):
        await charge(10, execution_grant=grant, execution_attempt_id="async-terminal")
    with pytest.raises(LegitimacyInvariantError, match="already partial"):
        await charge(10, execution_grant=grant, execution_attempt_id="async-terminal")
    assert calls == [10]
