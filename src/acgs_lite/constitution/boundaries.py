"""exp167: PolicyBoundary — hard permission ceilings for governance decisions.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BoundaryViolation:
    """Record of a policy boundary being crossed.

    Immutable verdict produced by :class:`PolicyBoundary` when an action
    would be allowed by rules but is blocked by a hard ceiling.
    """

    action: str
    boundary_id: str
    boundary_name: str
    reason: str
    severity: str = "critical"  # ceilings are always critical

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "boundary_id": self.boundary_id,
            "boundary_name": self.boundary_name,
            "reason": self.reason,
            "severity": self.severity,
        }


@dataclass
class PolicyBoundary:
    """Hard permission ceiling that overrides rule-based allow decisions.

    A ``PolicyBoundary`` defines absolute forbidden zones — actions that can
    never be allowed regardless of what constitutional rules say. This is a
    hard control boundary above the governance engine: even if a rule explicitly
    allows an action, a matching boundary will block it.

    Use cases:

    - Regulatory hard stops: PCI-DSS prohibits storing raw card numbers —
      no rule can override that.
    - MACI separation-of-powers: Executors cannot approve their own work —
      enforce it at the boundary level, not just the rule level.
    - Emergency kill-switches: During an incident, add a boundary to block
      all destructive actions until the incident is resolved.

    Usage::

        from acgs_lite.constitution.boundaries import PolicyBoundary, PolicyBoundarySet

        # Define a hard ceiling
        boundary = PolicyBoundary(
            boundary_id="PCI-001",
            name="No raw card storage",
            forbidden_keywords=["store card", "save credit card", "write card number"],
            forbidden_patterns=[r"4[0-9]{12}(?:[0-9]{3})?"],  # Visa pattern
            reason="PCI-DSS 3.2.1: raw PANs must never be stored",
        )

        boundaries = PolicyBoundarySet([boundary])

        # After the governance engine allows an action:
        result = boundaries.check("store card number 4111111111111111")
        if result["blocked"]:
            # Override the engine's allow — hard ceiling
            print(result["violations"])

    """

    boundary_id: str
    name: str
    reason: str
    forbidden_keywords: list[str] = field(default_factory=list)
    forbidden_patterns: list[str] = field(default_factory=list)
    severity: str = "critical"
    _compiled: list[re.Pattern[str]] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.forbidden_patterns]

    def matches(self, action: str) -> bool:
        """Return True if *action* crosses this boundary.

        Checks forbidden keywords (case-insensitive substring) first, then
        regex patterns for precision matching.

        Args:
            action: The action string to evaluate.

        Returns:
            True if the boundary forbids this action.
        """
        action_lower = action.lower()
        for kw in self.forbidden_keywords:
            if kw.lower() in action_lower:
                return True
        return any(pat.search(action) for pat in self._compiled)

    def violation(self, action: str) -> BoundaryViolation | None:
        """Return a BoundaryViolation if action crosses this boundary, else None."""
        if self.matches(action):
            return BoundaryViolation(
                action=action,
                boundary_id=self.boundary_id,
                boundary_name=self.name,
                reason=self.reason,
                severity=self.severity,
            )
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "name": self.name,
            "reason": self.reason,
            "forbidden_keywords": self.forbidden_keywords,
            "forbidden_patterns": self.forbidden_patterns,
            "severity": self.severity,
        }


class PolicyBoundarySet:
    """Ordered collection of :class:`PolicyBoundary` objects checked as a ceiling.

    Evaluates all boundaries against an action and returns a consolidated
    result. Designed to wrap a governance engine's "allow" verdict — if any
    boundary fires, the action is overridden to "blocked".

    Usage::

        boundaries = PolicyBoundarySet([
            PolicyBoundary("PCI-001", "No raw card storage",
                           reason="PCI-DSS 3.2.1",
                           forbidden_keywords=["store card number"]),
            PolicyBoundary("MACI-001", "No self-approval",
                           reason="MACI separation of powers",
                           forbidden_keywords=["self-approve", "auto-approve"]),
        ])

        result = boundaries.check("auto-approve my merge request")
        # {"blocked": True, "violations": [...], "checked": 2}

    """

    __slots__ = ("_boundaries",)

    def __init__(self, boundaries: list[PolicyBoundary] | None = None) -> None:
        self._boundaries: list[PolicyBoundary] = list(boundaries or [])

    def add(self, boundary: PolicyBoundary) -> None:
        """Add a boundary to the set."""
        self._boundaries.append(boundary)

    def remove(self, boundary_id: str) -> bool:
        """Remove boundary by ID. Returns True if found and removed."""
        before = len(self._boundaries)
        self._boundaries = [b for b in self._boundaries if b.boundary_id != boundary_id]
        return len(self._boundaries) < before

    def check(self, action: str) -> dict[str, Any]:
        """Check action against all boundaries.

        Args:
            action: The action string to evaluate.

        Returns:
            dict with:
                - ``blocked``: True if any boundary fires
                - ``violations``: list of BoundaryViolation dicts
                - ``checked``: number of boundaries evaluated
                - ``action``: the evaluated action
        """
        violations: list[dict[str, Any]] = []
        for boundary in self._boundaries:
            v = boundary.violation(action)
            if v is not None:
                violations.append(v.to_dict())
        return {
            "blocked": bool(violations),
            "violations": violations,
            "checked": len(self._boundaries),
            "action": action,
        }

    def check_batch(self, actions: list[str]) -> dict[str, Any]:
        """Check multiple actions against all boundaries.

        Args:
            actions: List of action strings to evaluate.

        Returns:
            dict with:
                - ``total``: number of actions checked
                - ``blocked_count``: number of actions blocked
                - ``results``: list of per-action check results
                - ``compliance_rate``: fraction of actions not blocked (0-1)
        """
        results = [self.check(action) for action in actions]
        blocked = sum(1 for r in results if r["blocked"])
        total = len(actions)
        return {
            "total": total,
            "blocked_count": blocked,
            "results": results,
            "compliance_rate": (total - blocked) / total if total else 1.0,
        }

    def summary(self) -> dict[str, Any]:
        """Return a summary of all registered boundaries.

        Returns:
            dict with ``count`` and ``boundaries`` list.
        """
        return {
            "count": len(self._boundaries),
            "boundaries": [b.to_dict() for b in self._boundaries],
        }

    def __len__(self) -> int:
        return len(self._boundaries)

    def __repr__(self) -> str:
        return f"PolicyBoundarySet({len(self._boundaries)} boundaries)"
