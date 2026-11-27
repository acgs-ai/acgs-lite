"""Cryptographically verifiable validator selection for governance quorums.

Selects a validator quorum for a governance case using deterministic,
verifiable randomness. The selection is:

- **Risk-scaled**: higher-risk cases get larger quorums (k).
- **Diversity-aware**: maximizes model/provider diversity when metadata is available.
- **MACI-enforced**: the producing agent is always excluded.
- **Verifiable**: anyone can re-derive the selection from the proof seed.
- **Trust-weighted**: higher-trust validators are more likely to be selected,
  but never guaranteed (preventing trust-based prediction attacks).

The selection proof contains enough information for independent re-verification
without access to the selector's internal state.

Example::

    from acgs_lite.constitution.validator_selection import (
        ValidatorPool,
        ValidatorSelector,
        SelectionPolicy,
    )

    pool = ValidatorPool()
    pool.register("val-1", trust_score=0.95, domains=["finance"], model="gpt-5.5")
    pool.register("val-2", trust_score=0.88, domains=["finance"], model="claude-sonnet-4-6")
    pool.register("val-3", trust_score=0.72, domains=["finance", "privacy"], model="gpt-5.5")
    pool.register("val-4", trust_score=0.91, domains=["finance"], model="gemini-2.5-flash")
    pool.register("val-5", trust_score=0.65, domains=["privacy"], model="claude-sonnet-4-6")

    selector = ValidatorSelector(pool=pool)
    result = selector.select(
        case_id="case-001",
        producer_id="miner-7",
        risk_tier="high",
        domain="finance",
    )

    assert result.producer_excluded  # miner-7 not in selected
    assert len(result.selected) >= 5  # high risk → k≥5
    assert result.verify()  # proof is independently verifiable

"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from acgs_lite._compat import constant_time_compare

# ── Risk tier → quorum size mapping ──────────────────────────────────────────

_DEFAULT_K_BY_RISK: dict[str, int] = {
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 9,
}

_DEFAULT_Q_FRACTION: float = 2 / 3  # quorum fraction (ceil)


# ── Data types ───────────────────────────────────────────────────────────────


@dataclass
class ValidatorInfo:
    """Registration record for a validator in the pool.

    Attributes:
        validator_id: Unique identifier.
        trust_score: Current trust score [0.0, 1.0].
        domains: Governance domains this validator covers.
        model: Underlying model/provider identifier (for diversity tracking).
        active: Whether the validator is currently available.
        metadata: Arbitrary extension data.
    """

    validator_id: str
    trust_score: float = 1.0
    domains: list[str] = field(default_factory=list)
    model: str = ""
    active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SelectionProof:
    """Cryptographic proof that a validator selection was fair.

    Contains everything needed for independent re-verification:
    the seed, the eligible set, the selection algorithm parameters,
    and the resulting selection order.

    Attributes:
        case_id: The case this selection was made for.
        seed: Hex-encoded random seed used for selection.
        eligible_ids: Sorted list of eligible validator IDs (post-exclusion).
        eligible_weights: Corresponding normalized weights.
        selected_ids: Validators selected, in selection order.
        k: Quorum size used.
        q: Approval threshold.
        risk_tier: Risk tier that determined k.
        producer_id: The excluded producer agent.
        domain: Governance domain of the case.
        timestamp: ISO-8601 selection timestamp.
        algorithm: Selection algorithm identifier.
        diversity_bonus: Whether diversity weighting was applied.
        signature: HMAC-SHA256 over canonical proof content.
    """

    case_id: str
    seed: str
    eligible_ids: list[str]
    eligible_weights: list[float]
    selected_ids: list[str]
    k: int
    q: int
    risk_tier: str
    producer_id: str
    domain: str
    timestamp: str
    algorithm: str = "weighted_shuffle_v1"
    diversity_bonus: bool = False
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Return deterministic canonical representation for signing/verification."""
        parts = [
            f"case:{self.case_id}",
            f"seed:{self.seed}",
            f"eligible:{','.join(self.eligible_ids)}",
            f"weights:{','.join(f'{w:.8f}' for w in self.eligible_weights)}",
            f"selected:{','.join(self.selected_ids)}",
            f"k:{self.k}",
            f"q:{self.q}",
            f"risk:{self.risk_tier}",
            f"producer:{self.producer_id}",
            f"domain:{self.domain}",
            f"ts:{self.timestamp}",
            f"algo:{self.algorithm}",
            f"diversity:{self.diversity_bonus}",
        ]
        return "|".join(parts).encode()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "seed": self.seed,
            "eligible_ids": self.eligible_ids,
            "eligible_weights": self.eligible_weights,
            "selected_ids": self.selected_ids,
            "k": self.k,
            "q": self.q,
            "risk_tier": self.risk_tier,
            "producer_id": self.producer_id,
            "domain": self.domain,
            "timestamp": self.timestamp,
            "algorithm": self.algorithm,
            "diversity_bonus": self.diversity_bonus,
            "signature": self.signature,
        }


@dataclass
class SelectionResult:
    """Result of validator selection for a governance case.

    Attributes:
        selected: List of selected validator IDs.
        k: Quorum size (number of validators selected).
        q: Approval threshold required.
        proof: Cryptographic selection proof.
        producer_excluded: Confirms the producer was excluded.
        diversity_score: 0.0–1.0 measuring model diversity in the selection.
        eligible_count: How many validators were eligible before selection.
        domain_coverage: Whether all selected validators cover the case domain.
    """

    selected: list[str]
    k: int
    q: int
    proof: SelectionProof
    producer_excluded: bool
    diversity_score: float
    eligible_count: int
    domain_coverage: bool

    def verify(self, signing_key: str = "") -> bool:
        """Re-derive the selection from the proof and verify consistency.

        This replays the weighted shuffle using the proof's seed and
        eligible set, then checks that the result matches selected_ids.
        If a signing_key is provided, also verifies the HMAC signature.

        Returns:
            True if the selection is independently verifiable.
        """
        # Re-derive selection using the same algorithm
        rederived = _weighted_shuffle_select(
            seed_hex=self.proof.seed,
            eligible_ids=self.proof.eligible_ids,
            weights=self.proof.eligible_weights,
            k=self.proof.k,
        )

        if rederived != self.proof.selected_ids:
            return False

        # Verify HMAC if key provided
        if signing_key and self.proof.signature:
            expected = hmac.new(
                signing_key.encode(),
                self.proof.canonical_bytes(),
                hashlib.sha256,
            ).hexdigest()
            if not constant_time_compare(expected, self.proof.signature):
                return False

        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected": self.selected,
            "k": self.k,
            "q": self.q,
            "producer_excluded": self.producer_excluded,
            "diversity_score": self.diversity_score,
            "eligible_count": self.eligible_count,
            "domain_coverage": self.domain_coverage,
            "proof": self.proof.to_dict(),
        }


@dataclass
class SelectionPolicy:
    """Configuration for validator selection behavior.

    Attributes:
        k_by_risk: Mapping of risk tier → quorum size.
        q_fraction: Fraction of k needed for approval (ceil applied).
        trust_weight_exponent: How strongly trust scores influence selection.
            0.0 = uniform random, 1.0 = linear, 2.0 = quadratic preference.
        diversity_bonus_factor: Weight bonus for underrepresented models.
            0.0 = no diversity preference, 1.0 = strong diversity preference.
        min_trust_threshold: Minimum trust score to be eligible.
        require_domain_match: If True, only domain-matched validators are eligible.
        signing_key: HMAC key for proof signatures (empty = unsigned).
    """

    k_by_risk: dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_K_BY_RISK))
    q_fraction: float = _DEFAULT_Q_FRACTION
    trust_weight_exponent: float = 1.0
    diversity_bonus_factor: float = 0.5
    min_trust_threshold: float = 0.0
    require_domain_match: bool = True
    signing_key: str = ""


# ── Pool ─────────────────────────────────────────────────────────────────────


class ValidatorPool:
    """Registry of available validators with trust and capability metadata.

    Thread-safe for reads; mutations should be serialized by the caller.

    Example::

        pool = ValidatorPool()
        pool.register("val-1", trust_score=0.95, domains=["finance"])
        pool.register("val-2", trust_score=0.88, domains=["finance", "privacy"])
        pool.update_trust("val-1", 0.90)
        pool.deactivate("val-2")
    """

    def __init__(self) -> None:
        self._validators: dict[str, ValidatorInfo] = {}

    def register(
        self,
        validator_id: str,
        *,
        trust_score: float = 1.0,
        domains: list[str] | None = None,
        model: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> ValidatorInfo:
        """Register a validator. Overwrites if already registered."""
        if not (0.0 <= trust_score <= 1.0):
            raise ValueError(f"trust_score must be in [0.0, 1.0], got {trust_score}")
        info = ValidatorInfo(
            validator_id=validator_id,
            trust_score=trust_score,
            domains=list(domains) if domains else [],
            model=model,
            active=True,
            metadata=metadata or {},
        )
        self._validators[validator_id] = info
        return info

    def update_trust(self, validator_id: str, trust_score: float) -> None:
        """Update a validator's trust score."""
        if validator_id not in self._validators:
            raise KeyError(f"Validator {validator_id!r} not registered")
        if not (0.0 <= trust_score <= 1.0):
            raise ValueError(f"trust_score must be in [0.0, 1.0], got {trust_score}")
        self._validators[validator_id].trust_score = trust_score

    def deactivate(self, validator_id: str) -> None:
        """Mark a validator as inactive (unavailable for selection)."""
        if validator_id not in self._validators:
            raise KeyError(f"Validator {validator_id!r} not registered")
        self._validators[validator_id].active = False

    def activate(self, validator_id: str) -> None:
        """Mark a validator as active."""
        if validator_id not in self._validators:
            raise KeyError(f"Validator {validator_id!r} not registered")
        self._validators[validator_id].active = True

    def get(self, validator_id: str) -> ValidatorInfo | None:
        """Return validator info or None if not registered."""
        return self._validators.get(validator_id)

    def eligible(
        self,
        *,
        exclude: set[str] | None = None,
        domain: str = "",
        require_domain: bool = True,
        min_trust: float = 0.0,
    ) -> list[ValidatorInfo]:
        """Return active, eligible validators after applying filters.

        Args:
            exclude: Validator IDs to exclude (e.g. the producer).
            domain: Required governance domain (empty = any).
            require_domain: If True and domain is set, only include domain matches.
            min_trust: Minimum trust score threshold.

        Returns:
            List of eligible ValidatorInfo, sorted by validator_id for determinism.
        """
        excluded = exclude or set()
        result: list[ValidatorInfo] = []
        for v in self._validators.values():
            if not v.active:
                continue
            if v.validator_id in excluded:
                continue
            if v.trust_score < min_trust:
                continue
            if (
                domain
                and require_domain
                and v.domains
                and domain.lower() not in (d.lower() for d in v.domains)
            ):
                continue
            result.append(v)
        result.sort(key=lambda v: v.validator_id)
        return result

    def monoculture_report(self, domain: str = "") -> dict[str, Any]:
        """Report model diversity among active validators.

        Returns:
            dict with model_distribution, dominant_model, diversity_score,
            and monoculture_risk flag.
        """
        eligible = self.eligible(domain=domain, require_domain=bool(domain))
        if not eligible:
            return {
                "model_distribution": {},
                "dominant_model": "",
                "diversity_score": 0.0,
                "monoculture_risk": True,
                "total_validators": 0,
            }

        models: dict[str, int] = {}
        for v in eligible:
            m = v.model or "unknown"
            models[m] = models.get(m, 0) + 1

        total = len(eligible)
        dominant = max(models, key=models.get)  # type: ignore[arg-type]
        dominant_frac = models[dominant] / total

        # Shannon entropy normalized to [0, 1]
        if len(models) <= 1:
            diversity = 0.0
        else:
            entropy = -sum((c / total) * math.log2(c / total) for c in models.values() if c > 0)
            max_entropy = math.log2(len(models))
            diversity = entropy / max_entropy if max_entropy > 0 else 0.0

        return {
            "model_distribution": models,
            "dominant_model": dominant,
            "dominant_fraction": round(dominant_frac, 4),
            "diversity_score": round(diversity, 4),
            "monoculture_risk": dominant_frac > 0.66,
            "total_validators": total,
        }

    def list_validators(self, *, active_only: bool = True) -> list[str]:
        """Return sorted validator IDs."""
        return sorted(
            v.validator_id for v in self._validators.values() if not active_only or v.active
        )

    def __len__(self) -> int:
        return sum(1 for v in self._validators.values() if v.active)

    def __repr__(self) -> str:
        active = sum(1 for v in self._validators.values() if v.active)
        return f"ValidatorPool({len(self._validators)} registered, {active} active)"


# ── Core selection algorithm ─────────────────────────────────────────────────


def _weighted_shuffle_select(
    seed_hex: str,
    eligible_ids: list[str],
    weights: list[float],
    k: int,
) -> list[str]:
    """Deterministic weighted selection without replacement.

    Uses the seed to generate per-candidate sort keys:
        key_i = -log(HMAC(seed, id_i)) / weight_i

    This is the Efraimidis-Spirakis weighted reservoir sampling algorithm,
    which produces a weighted random sample without replacement in O(n log n).
    The selection is fully deterministic given the seed, making it verifiable.

    Args:
        seed_hex: Hex-encoded random seed.
        eligible_ids: Sorted list of eligible validator IDs.
        weights: Corresponding non-negative weights (same length as eligible_ids).
        k: Number of validators to select.

    Returns:
        List of k selected validator IDs in selection order.
    """
    if len(eligible_ids) != len(weights):
        raise ValueError("eligible_ids and weights must have the same length")
    if k > len(eligible_ids):
        # If we need more than available, return all (caller handles the shortage)
        k = len(eligible_ids)
    if k == 0:
        return []

    seed_bytes = bytes.fromhex(seed_hex)

    # Generate deterministic sort keys using Efraimidis-Spirakis
    keyed: list[tuple[float, str]] = []
    for vid, w in zip(eligible_ids, weights, strict=True):
        # HMAC-SHA256 gives us a deterministic pseudo-random value per validator
        h = hmac.new(seed_bytes, vid.encode(), hashlib.sha256).digest()
        # Convert first 8 bytes to a uniform float in (0, 1)
        u = (int.from_bytes(h[:8], "big") + 1) / (2**64 + 1)
        # Efraimidis-Spirakis key: u^(1/weight)
        # Using log form for numerical stability: log(u) / weight
        # Higher weight → less negative key → more likely to be selected
        effective_w = max(w, 1e-10)  # prevent division by zero
        key = math.log(u) / effective_w
        keyed.append((key, vid))

    # Sort descending by key (highest keys = selected)
    keyed.sort(key=lambda x: x[0], reverse=True)

    return [vid for _, vid in keyed[:k]]


def _compute_diversity_weights(
    eligible: list[ValidatorInfo],
    base_weights: list[float],
    bonus_factor: float,
) -> list[float]:
    """Apply diversity bonus to underrepresented models.

    Validators using less common models get a weight boost proportional
    to the inverse of their model's frequency in the eligible set.

    Args:
        eligible: Eligible validators.
        base_weights: Trust-derived base weights.
        bonus_factor: Strength of diversity bonus [0.0, 1.0].

    Returns:
        Adjusted weights with diversity bonus applied.
    """
    if bonus_factor <= 0 or not eligible:
        return list(base_weights)

    # Count model frequencies
    model_counts: dict[str, int] = {}
    for v in eligible:
        m = v.model or "unknown"
        model_counts[m] = model_counts.get(m, 0) + 1

    total = len(eligible)
    adjusted: list[float] = []
    for v, w in zip(eligible, base_weights, strict=True):
        m = v.model or "unknown"
        freq = model_counts[m] / total
        # Inverse frequency bonus: rare models get higher bonus
        # At freq=1.0 (monoculture): bonus=0. At freq=0.1: bonus ≈ 0.9 * factor
        diversity_bonus = (1.0 - freq) * bonus_factor
        adjusted.append(w * (1.0 + diversity_bonus))

    return adjusted


# ── Selector ─────────────────────────────────────────────────────────────────


class ValidatorSelector:
    """Selects validator quorums for governance cases.

    Combines risk-scaled quorum sizing, trust-weighted random selection,
    model diversity optimization, and MACI producer exclusion into a single
    verifiable selection step.

    Args:
        pool: The validator pool to select from.
        policy: Selection policy configuration.

    Example::

        selector = ValidatorSelector(pool=pool)
        result = selector.select(
            case_id="case-001",
            producer_id="miner-7",
            risk_tier="high",
            domain="finance",
        )

        # Verify the selection is fair
        assert result.verify()

        # Use selected validators for quorum gate
        from acgs_lite.constitution.quorum import QuorumManager
        mgr = QuorumManager()
        gate_id = mgr.open(
            action=f"validate-{result.proof.case_id}",
            required_approvals=result.q,
            eligible_voters=set(result.selected),
        )
    """

    def __init__(
        self,
        pool: ValidatorPool,
        policy: SelectionPolicy | None = None,
    ) -> None:
        self.pool = pool
        self.policy = policy or SelectionPolicy()

    def select(
        self,
        case_id: str,
        producer_id: str,
        risk_tier: str = "medium",
        domain: str = "",
        *,
        k_override: int | None = None,
        seed: str | None = None,
        _now: datetime | None = None,
    ) -> SelectionResult:
        """Select a validator quorum for a governance case.

        Args:
            case_id: Unique case identifier.
            producer_id: The agent that produced the work (excluded from selection).
            risk_tier: Risk tier ("low", "medium", "high", "critical").
            domain: Governance domain of the case.
            k_override: Override the risk-tier-based quorum size.
            seed: Override random seed (hex string; for testing/replay).
            _now: Override current time (for testing).

        Returns:
            SelectionResult with selected validators and proof.

        Raises:
            ValueError: If not enough eligible validators for the quorum.
        """
        now = _now or datetime.now(timezone.utc)
        tier = risk_tier.lower()
        pol = self.policy

        # Determine quorum size k
        k = k_override if k_override is not None else pol.k_by_risk.get(tier, 3)
        q = math.ceil(k * pol.q_fraction)

        # Generate or use provided seed
        if seed is None:
            seed = secrets.token_hex(32)

        # Get eligible validators (exclude producer, filter by domain/trust)
        eligible = self.pool.eligible(
            exclude={producer_id},
            domain=domain,
            require_domain=pol.require_domain_match and bool(domain),
            min_trust=pol.min_trust_threshold,
        )

        eligible_count = len(eligible)

        if eligible_count < k:
            if eligible_count == 0:
                raise ValueError(
                    f"No eligible validators for case {case_id!r} "
                    f"(domain={domain!r}, producer={producer_id!r})"
                )
            # Degrade gracefully: use all available, adjust q
            k = eligible_count
            q = math.ceil(k * pol.q_fraction)

        # Compute base weights from trust scores
        base_weights = [v.trust_score**pol.trust_weight_exponent for v in eligible]

        # Apply diversity bonus
        use_diversity = pol.diversity_bonus_factor > 0
        if use_diversity:
            weights = _compute_diversity_weights(eligible, base_weights, pol.diversity_bonus_factor)
        else:
            weights = base_weights

        # Normalize weights
        total_w = sum(weights)
        if total_w <= 0:
            normalized = [1.0 / len(weights)] * len(weights)
        else:
            normalized = [w / total_w for w in weights]

        eligible_ids = [v.validator_id for v in eligible]

        # Run selection
        selected_ids = _weighted_shuffle_select(
            seed_hex=seed,
            eligible_ids=eligible_ids,
            weights=normalized,
            k=k,
        )

        # Compute diversity score of the selection
        selected_set = set(selected_ids)
        selected_validators = [v for v in eligible if v.validator_id in selected_set]
        diversity_score = self._diversity_score(selected_validators)

        # Check domain coverage
        domain_coverage = True
        if domain:
            for v in selected_validators:
                if v.domains and domain.lower() not in (d.lower() for d in v.domains):
                    domain_coverage = False
                    break

        # Build proof
        proof = SelectionProof(
            case_id=case_id,
            seed=seed,
            eligible_ids=eligible_ids,
            eligible_weights=normalized,
            selected_ids=selected_ids,
            k=k,
            q=q,
            risk_tier=tier,
            producer_id=producer_id,
            domain=domain,
            timestamp=now.isoformat(),
            algorithm="weighted_shuffle_v1",
            diversity_bonus=use_diversity,
        )

        # Sign if key configured
        if pol.signing_key:
            proof.signature = hmac.new(
                pol.signing_key.encode(),
                proof.canonical_bytes(),
                hashlib.sha256,
            ).hexdigest()

        return SelectionResult(
            selected=selected_ids,
            k=k,
            q=q,
            proof=proof,
            producer_excluded=producer_id not in selected_set,
            diversity_score=diversity_score,
            eligible_count=eligible_count,
            domain_coverage=domain_coverage,
        )

    @staticmethod
    def _diversity_score(validators: list[ValidatorInfo]) -> float:
        """Compute normalized Shannon entropy of model distribution."""
        if len(validators) <= 1:
            return 0.0
        models: dict[str, int] = {}
        for v in validators:
            m = v.model or "unknown"
            models[m] = models.get(m, 0) + 1
        if len(models) <= 1:
            return 0.0
        total = len(validators)
        entropy = -sum((c / total) * math.log2(c / total) for c in models.values() if c > 0)
        max_entropy = math.log2(len(models))
        return round(entropy / max_entropy, 4) if max_entropy > 0 else 0.0

    @staticmethod
    def verify_selection(proof: SelectionProof, signing_key: str = "") -> bool:
        """Independently verify a selection proof.

        Re-runs the weighted shuffle algorithm with the proof's seed
        and eligible set, then checks the result matches.

        Args:
            proof: The selection proof to verify.
            signing_key: HMAC key for signature verification (optional).

        Returns:
            True if the selection is verified as correct.
        """
        rederived = _weighted_shuffle_select(
            seed_hex=proof.seed,
            eligible_ids=proof.eligible_ids,
            weights=proof.eligible_weights,
            k=proof.k,
        )

        if rederived != proof.selected_ids:
            return False

        if signing_key and proof.signature:
            expected = hmac.new(
                signing_key.encode(),
                proof.canonical_bytes(),
                hashlib.sha256,
            ).hexdigest()
            if not constant_time_compare(expected, proof.signature):
                return False

        return True
