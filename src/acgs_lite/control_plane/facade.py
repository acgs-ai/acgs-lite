"""One constructor that wires every control-plane layer consistently.

:func:`build_control_plane` builds the immutable-core registry, the signed
receipt ledger, the signed run registry, oversight telemetry, the approval
gate, the kill switch, the PDP (bound to all of them), repository
permissions, scoped credentials, budgets, autonomy, the trigger breaker,
runbooks with a post-hoc review queue, change ownership, the incident lock,
the deterministic evaluator service, the independent verifier and the
promotion gate -- and the dispatcher that enforces them. Every layer is
required: a missing (``None``) or mistyped config field raises
:class:`ControlPlaneConfigError`, so a misconfiguration can never silently
disable a layer.

All stores live in the agent-unwritable core of ``repo_root``:
``audit/receipts.jsonl``, ``audit/runs.jsonl``,
``audit/oversight-telemetry.jsonl``, ``control-plane/halt/`` and
``control-plane/incident/``. Phase 6a: the identity directory
(``identity_path``, IAM core) attests every principal's kind; the credential
issuer, the dispatcher and every admin registry are bound to it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acgs_lite.control_plane.approvals import (
    DEFAULT_QUORUM_POLICIES,
    ApprovalAuthority,
    ApprovalGate,
    QuorumPolicy,
)
from acgs_lite.control_plane.autonomy import AutonomyController, ErrorBudget
from acgs_lite.control_plane.breaker import BreakerPolicy, TriggerCircuitBreaker, TriggerRegistry
from acgs_lite.control_plane.budgets import BudgetLedger, BudgetLimits
from acgs_lite.control_plane.change_ownership import ChangeOwnershipRegistry
from acgs_lite.control_plane.credentials import CredentialIssuer
from acgs_lite.control_plane.dispatcher import GovernedToolDispatcher
from acgs_lite.control_plane.evaluator import (
    DEFAULT_SCORE_GRANULARITY,
    DEFAULT_SUBMISSION_WINDOW_S,
    DEFAULT_SUBMISSIONS_PER_WINDOW,
    DeterministicEvaluator,
    EvaluatorService,
)
from acgs_lite.control_plane.evidence import ExternalRunVerifier, TrustedRunRegistry
from acgs_lite.control_plane.iam import RepositoryPermissions, WriteGrant
from acgs_lite.control_plane.identity import (
    AdminAttestor,
    HumanAuthenticator,
    IdentityDirectoryError,
    StaticIdentityDirectory,
)
from acgs_lite.control_plane.immutable_core import (
    DEFAULT_IMMUTABLE_CORE,
    CoreCategory,
    ImmutableCoreRegistry,
)
from acgs_lite.control_plane.incident import IncidentMutationLock
from acgs_lite.control_plane.killswitch import KillSwitch
from acgs_lite.control_plane.pdp import PolicyDecisionPoint
from acgs_lite.control_plane.policy import PolicySet
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.promotion import PromotionGate
from acgs_lite.control_plane.receipt_ledger import JSONLReceiptStore, ReceiptLedger
from acgs_lite.control_plane.receipt_verify import ReceiptVerification, verify_chain
from acgs_lite.control_plane.roles import RoleAssignments
from acgs_lite.control_plane.runbook import DEFAULT_MAX_RUNBOOK_AGE_DAYS, RunbookRegistry
from acgs_lite.control_plane.telemetry import (
    JSONLTelemetryStore,
    OversightMetrics,
    TelemetryRecorder,
)
from acgs_lite.control_plane.tier_policy import DEFAULT_NARROW_MAX_BLAST_RADIUS, ReviewQueue
from acgs_lite.control_plane.tiers import ActionTier
from acgs_lite.control_plane.verifier import IndependentVerifier, VerifierPolicy
from acgs_lite.legitimacy.signing import ReceiptSigner

__all__ = [
    "RECEIPTS_PATH",
    "RUNS_PATH",
    "TELEMETRY_PATH",
    "ControlPlane",
    "ControlPlaneConfig",
    "ControlPlaneConfigError",
    "build_control_plane",
]

RECEIPTS_PATH = "audit/receipts.jsonl"
RUNS_PATH = "audit/runs.jsonl"
TELEMETRY_PATH = "audit/oversight-telemetry.jsonl"


class ControlPlaneConfigError(ValueError):
    """A layer is missing or misconfigured."""


@dataclass(frozen=True)
class ControlPlaneConfig:
    """Every field without a default is a required layer input."""

    repo_root: str
    system_id: str
    constitution: Any
    policy_path: str
    """Repo-relative POLICY core file holding the declarative PolicySet."""
    heldout_suite_path: str
    """Repo-relative HELDOUT_DATA core file (the evaluator's suite)."""
    identity_path: str
    """Repo-relative IAM core file: the identity directory (Phase 6a), e.g.
    ``iam/identities.yaml``. Its single admin must be :attr:`admin`."""
    admin: Principal
    """HUMAN admin registering approvers, runbooks, triggers and changes.
    Every admin call needs ``admin_credential=``: a credential from
    :meth:`CredentialIssuer.issue_for_human` with scope ``admin:control-plane``."""
    harness: Principal
    """SERVICE principal of the harness (telemetry, evaluator, runs)."""
    ledger_signer: ReceiptSigner
    run_registry_signer: ReceiptSigner
    verifier_factory: Callable[[ExternalRunVerifier], IndependentVerifier]
    proposer_model_family: str
    proposer_vendor: str
    write_grants: tuple[WriteGrant, ...]
    budget_limits: BudgetLimits
    error_budget: ErrorBudget
    breaker_policy: BreakerPolicy
    tool_tiers: Mapping[str, ActionTier] = field(default_factory=dict)
    read_only_tools: frozenset[str] = frozenset()
    # default_factory: Python 3.11 rejects an unhashable MappingProxyType as a
    # dataclass default (3.10 and 3.12+ accept it), breaking the package import.
    quorum_policies: Mapping[ActionTier, QuorumPolicy] = field(
        default_factory=lambda: DEFAULT_QUORUM_POLICIES
    )
    core_registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE
    max_runbook_age_days: int = DEFAULT_MAX_RUNBOOK_AGE_DAYS
    narrow_max_blast_radius: int = DEFAULT_NARROW_MAX_BLAST_RADIUS
    pre_denial_receipt_limit: int | None = None
    """``None`` receipts every pre-denial (no rate-limited suppression)."""
    backup_workflows: frozenset[str] = frozenset()
    """Run providers whose runs may prove a backup for agent T3 actions."""
    submissions_per_window: int = DEFAULT_SUBMISSIONS_PER_WINDOW
    submission_window_s: float = DEFAULT_SUBMISSION_WINDOW_S
    score_granularity: float = DEFAULT_SCORE_GRANULARITY


@dataclass(frozen=True)
class ControlPlane:
    """Every harness object, built by :func:`build_control_plane`. The agent
    process must only ever receive :attr:`dispatcher` and narrow handles."""

    config: ControlPlaneConfig
    registry: ImmutableCoreRegistry
    ledger: ReceiptLedger
    runs: TrustedRunRegistry
    telemetry_store: JSONLTelemetryStore
    telemetry: TelemetryRecorder
    authority: ApprovalAuthority
    gate: ApprovalGate
    kill_switch: KillSwitch
    pdp: PolicyDecisionPoint
    permissions: RepositoryPermissions
    credentials: CredentialIssuer
    budgets: BudgetLedger
    autonomy: AutonomyController
    triggers: TriggerRegistry
    breaker: TriggerCircuitBreaker
    runbooks: RunbookRegistry
    review_queue: ReviewQueue
    ownership: ChangeOwnershipRegistry
    incident_lock: IncidentMutationLock
    roles: RoleAssignments
    evaluator: DeterministicEvaluator
    evaluator_service: EvaluatorService
    verifier: IndependentVerifier
    verifier_policy: VerifierPolicy
    promotion: PromotionGate
    dispatcher: GovernedToolDispatcher
    identity: StaticIdentityDirectory
    human_authenticator: HumanAuthenticator
    """Challenge-response for HUMAN credentials (harness side only)."""
    admin_attestor: AdminAttestor

    def telemetry_snapshot(self) -> dict[str, Any]:
        """Phase-4 oversight metrics plus the post-hoc review backlog."""
        snapshot = OversightMetrics(self.telemetry_store).snapshot()
        snapshot["post_hoc_review"] = self.review_queue.snapshot()
        return snapshot

    def verify_receipts(self) -> ReceiptVerification:
        """Independent chain verification against the ledger's public key."""
        return verify_chain(
            self.ledger.receipts(),
            trusted_public_keys={self.ledger.key_id: self.ledger.public_key_hex},
            run_verifier=self.runs,
            expected_head_hash=self.ledger.head_hash,
            expected_ledger_id=self.ledger.ledger_id,
        )

    def start_agent_run(self, agent: Principal) -> None:
        """Start *agent*'s budget run with the configured limits (harness)."""
        self.budgets.start_run(agent, self.config.budget_limits)

    def submission_handle(self, agent: Principal) -> Callable[[Mapping[str, str]], float]:
        """The score-only evaluation callable for *agent* (budget-charged,
        rate-limited, coarse) -- the only evaluator handle an agent gets."""
        return self.evaluator_service.submission_handle(
            agent,
            self.budgets,
            max_per_window=self.config.submissions_per_window,
            window_s=self.config.submission_window_s,
            granularity=self.config.score_granularity,
        )

    def close(self) -> None:
        self.pdp.close()


def _require(config: ControlPlaneConfig, name: str, kind: type | tuple[type, ...]) -> Any:
    value = getattr(config, name, None)
    if value is None:
        raise ControlPlaneConfigError(f"control-plane layer input {name!r} is missing")
    if not isinstance(value, kind):
        raise ControlPlaneConfigError(f"control-plane input {name!r} has the wrong type")
    return value


def _require_kind(principal: Principal, kind: PrincipalKind, name: str) -> None:
    if principal.kind is not kind:
        raise ControlPlaneConfigError(f"{name} must be a {kind.value} principal")


def _require_category(
    registry: ImmutableCoreRegistry, path: str, category: CoreCategory, name: str
) -> None:
    if registry.classify(path) is not category:
        raise ControlPlaneConfigError(f"{name} {path!r} must be immutable-core {category.value}")


def build_control_plane(config: ControlPlaneConfig) -> ControlPlane:
    """Construct every layer from *config*; raise :class:`ControlPlaneConfigError`
    for any missing or inconsistent input."""
    if not isinstance(config, ControlPlaneConfig):
        raise ControlPlaneConfigError("config must be a ControlPlaneConfig")
    repo_root = _require(config, "repo_root", str)
    if not Path(repo_root).is_absolute() or not Path(repo_root).is_dir():
        raise ControlPlaneConfigError("repo_root must be an existing absolute directory")
    system_id = _require(config, "system_id", str)
    if config.constitution is None:
        raise ControlPlaneConfigError("control-plane layer input 'constitution' is missing")
    admin = _require(config, "admin", Principal)
    harness = _require(config, "harness", Principal)
    _require_kind(admin, PrincipalKind.HUMAN, "admin")
    _require_kind(harness, PrincipalKind.SERVICE, "harness")
    ledger_signer = _require(config, "ledger_signer", ReceiptSigner)
    run_signer = _require(config, "run_registry_signer", ReceiptSigner)
    if ledger_signer.public_key_hex() == run_signer.public_key_hex():
        raise ControlPlaneConfigError("ledger and run registry need distinct signing keys")
    if not callable(config.verifier_factory):
        raise ControlPlaneConfigError("control-plane layer input 'verifier_factory' is missing")
    family = _require(config, "proposer_model_family", str)
    vendor = _require(config, "proposer_vendor", str)
    grants: Iterable[WriteGrant] = _require(config, "write_grants", tuple)
    _require(config, "budget_limits", BudgetLimits)
    error_budget = _require(config, "error_budget", ErrorBudget)
    breaker_policy = _require(config, "breaker_policy", BreakerPolicy)
    core = _require(config, "core_registry", ImmutableCoreRegistry)
    registry = core.with_repo_root(repo_root)
    policy_path = _require(config, "policy_path", str)
    suite_path = _require(config, "heldout_suite_path", str)
    _require_category(registry, policy_path, CoreCategory.POLICY, "policy_path")
    _require_category(registry, suite_path, CoreCategory.HELDOUT_DATA, "heldout_suite_path")
    identity_path = _require(config, "identity_path", str)
    _require_category(registry, identity_path, CoreCategory.IAM, "identity_path")
    try:
        identity = StaticIdentityDirectory.load(identity_path, registry)
    except IdentityDirectoryError as exc:
        raise ControlPlaneConfigError(f"identity directory unloadable: {exc}") from exc
    directory_admin = identity.admin
    if (
        directory_admin.canonical_id != admin.canonical_id
        or directory_admin.kind is not admin.kind
        or directory_admin.system_id != admin.system_id
    ):
        raise ControlPlaneConfigError("admin must be the identity directory's single admin")
    harness_entry = identity.lookup(harness.id)
    if (
        harness_entry is None
        or harness_entry.kind is not PrincipalKind.SERVICE
        or harness_entry.system_id != harness.system_id
    ):
        raise ControlPlaneConfigError("harness must be a service entry in the identity directory")
    try:
        policy_set = PolicySet.from_yaml(Path(repo_root) / policy_path)
    except Exception as exc:
        raise ControlPlaneConfigError(f"policy set unloadable: {exc}") from exc

    ledger = ReceiptLedger(ledger_signer, store=JSONLReceiptStore(RECEIPTS_PATH, registry=registry))
    runs = TrustedRunRegistry(path=RUNS_PATH, registry=registry, signer=run_signer)
    telemetry_store = JSONLTelemetryStore(TELEMETRY_PATH, registry=registry)
    credentials = CredentialIssuer(registry=registry, identity=identity)
    attestor = AdminAttestor(credentials)
    telemetry = TelemetryRecorder(telemetry_store, harness, admin_attestor=attestor)
    authenticator = credentials.human_authenticator
    if authenticator is None:  # pragma: no cover - identity is set
        raise ControlPlaneConfigError("credential issuer has no human authenticator")
    authority = ApprovalAuthority(admin_attestor=attestor)
    gate = ApprovalGate(authority, policies=config.quorum_policies, telemetry=telemetry)
    kill_switch = KillSwitch(system_id, registry=registry, admin_attestor=attestor)
    pdp = PolicyDecisionPoint.for_constitution(
        config.constitution,
        policy_set,
        registry=registry,
        receipt_ledger=ledger,
        approval_gate=gate,
        kill_switch=kill_switch,
        telemetry=telemetry,
        pre_denial_receipt_limit=config.pre_denial_receipt_limit,
    )
    try:
        permissions = RepositoryPermissions(registry, grants)
        budgets = BudgetLedger()
        autonomy = AutonomyController(
            error_budget, budgets, kill_switch=kill_switch, pdp=pdp, admin_attestor=attestor
        )
        triggers = TriggerRegistry(admin_attestor=attestor)
        breaker = TriggerCircuitBreaker(
            breaker_policy, telemetry_store, autonomy, registry=triggers, admin_attestor=attestor
        )
        roles = RoleAssignments(admin, pdp=pdp, admin_attestor=attestor)
        runbooks = RunbookRegistry(
            registry,
            pdp=pdp,
            roles=roles,
            max_runbook_age_days=config.max_runbook_age_days,
            admin_attestor=attestor,
        )
        review_queue = ReviewQueue(admin_attestor=attestor)
        ownership = ChangeOwnershipRegistry(registry, admin=admin, admin_attestor=attestor)
        incident_lock = IncidentMutationLock(
            registry=registry, roles=roles, pdp=pdp, admin_attestor=attestor
        )
        evaluator = DeterministicEvaluator(suite_path, registry=registry)
        evaluator_service = EvaluatorService(evaluator, harness, runs)
        verifier = config.verifier_factory(runs)
        verifier_policy = VerifierPolicy(runs, telemetry=telemetry)
        verifier_policy.require_independent(family, vendor, verifier)
        promotion = PromotionGate(
            ledger,
            runs,
            pdp=pdp,
            roles=roles,
            incident_lock=incident_lock,
            admin_attestor=attestor,
        )
        dispatcher = GovernedToolDispatcher(
            pdp,
            permissions=permissions,
            tool_tiers=dict(config.tool_tiers),
            read_only_tools=frozenset(config.read_only_tools),
            kill_switch=kill_switch,
            credential_issuer=credentials,
            require_credential=True,
            budgets=budgets,
            autonomy=autonomy,
            breaker=breaker,
            runbooks=runbooks,
            review_queue=review_queue,
            ownership=ownership,
            incident_lock=incident_lock,
            run_verifier=runs,
            backup_workflows=config.backup_workflows,
            narrow_max_blast_radius=config.narrow_max_blast_radius,
        )
    except ControlPlaneConfigError:
        pdp.close()
        raise
    except Exception as exc:
        pdp.close()
        raise ControlPlaneConfigError(f"control-plane construction failed: {exc}") from exc
    return ControlPlane(
        config=config,
        registry=registry,
        ledger=ledger,
        runs=runs,
        telemetry_store=telemetry_store,
        telemetry=telemetry,
        authority=authority,
        gate=gate,
        kill_switch=kill_switch,
        pdp=pdp,
        permissions=permissions,
        credentials=credentials,
        budgets=budgets,
        autonomy=autonomy,
        triggers=triggers,
        breaker=breaker,
        runbooks=runbooks,
        review_queue=review_queue,
        ownership=ownership,
        incident_lock=incident_lock,
        roles=roles,
        evaluator=evaluator,
        evaluator_service=evaluator_service,
        verifier=verifier,
        verifier_policy=verifier_policy,
        promotion=promotion,
        dispatcher=dispatcher,
        identity=identity,
        human_authenticator=authenticator,
        admin_attestor=attestor,
    )
