"""Constitutional rules — the core of ACGS-Lite.

A Constitution is a set of Rules that govern agent behavior.
Rules can be loaded from YAML, dicts, or created programmatically.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, Field, field_validator, model_validator

from .analytics import _KW_NEGATIVE_RE, _NEGATIVE_VERBS_RE, _POSITIVE_VERBS_SET

# ── module-level helpers ────────────────────────────────────────────────────


def _parse_iso(s: str) -> datetime:
    """Parse an ISO-8601 date or datetime string into a :class:`datetime`.

    Bare dates (``YYYY-MM-DD``) are normalised to midnight.
    """
    if len(s) == 10 and s[4] == "-":
        s = s + "T00:00:00"
    return datetime.fromisoformat(s)


def _cosine_sim(a: list[float], b: list[float]) -> float | None:
    """Cosine similarity between two equal-length float vectors.

    Returns a float in [-1.0, 1.0], or ``None`` if either vector is empty,
    has mismatched length, or zero magnitude.
    """
    if not a or not b or len(a) != len(b):
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a == 0.0 or mag_b == 0.0:
        return None
    return float(dot / (mag_a * mag_b))


class Severity(str, Enum):
    """Rule severity levels."""

    CRITICAL = "critical"  # Blocks action, no override
    HIGH = "high"  # Blocks action, can be overridden with justification
    MEDIUM = "medium"  # Warns but allows
    LOW = "low"  # Informational

    def blocks(self) -> bool:
        """Whether this severity level blocks execution."""
        return self in (Severity.CRITICAL, Severity.HIGH)


class ViolationAction(str, Enum):
    """Enforcement action taken when a rule violation is detected.

    WARN             – Log a warning; allow the action to proceed.
    BLOCK            – Reject the action immediately (default when a rule fires).
    BLOCK_AND_NOTIFY – Reject and emit a notification event.
    REQUIRE_HUMAN_REVIEW – Queue for asynchronous human review; block until reviewed.
    ESCALATE         – Escalate to a senior governance reviewer.
    HALT             – Immediately halt the agent (circuit-breaker).
    """

    WARN = "warn"
    BLOCK = "block"
    BLOCK_AND_NOTIFY = "block_and_notify"
    REQUIRE_HUMAN_REVIEW = "require_human_review"
    ESCALATE = "escalate_to_senior"
    HALT = "halt_and_alert"


@dataclass(frozen=True, slots=True)
class AcknowledgedTension:
    """Recorded acknowledgement for a known merge-time rule tension."""

    rule_id: str
    rationale: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("AcknowledgedTension.rule_id cannot be empty")


class RuleSynthesisProvider(Protocol):
    """Typed interface for pluggable LLM-backed rule synthesis."""

    def generate_rule(self, description: str, *, rule_id: str) -> Mapping[str, Any]:
        """Generate rule fields from natural language policy text."""


def _extract_keywords(description: str, *, max_keywords: int = 6) -> list[str]:
    """Derive stable keyword candidates from free-form rule descriptions."""
    stop_words = {
        "the",
        "and",
        "or",
        "for",
        "with",
        "from",
        "must",
        "mustn't",
        "should",
        "cannot",
        "without",
        "into",
        "their",
        "your",
        "this",
        "that",
        "only",
        "allow",
        "allows",
        "ensure",
        "ensures",
    }
    tokens = re.findall(r"[a-z0-9][a-z0-9_\-]{2,}", description.lower())
    keywords: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        if token in stop_words or token in seen:
            continue
        keywords.append(token)
        seen.add(token)
        if len(keywords) >= max_keywords:
            break
    return keywords


def _heuristic_rule_payload(
    description: str,
    *,
    rule_id: str = "",
    default_severity: Severity = Severity.HIGH,
) -> dict[str, Any]:
    """Fallback rule synthesis when no external LLM provider is configured."""
    desc = description.strip()
    desc_lower = desc.lower()

    severity = default_severity
    if any(token in desc_lower for token in ("must not", "never", "prohibit", "forbid", "block")):
        severity = Severity.CRITICAL
    elif any(token in desc_lower for token in ("warn", "informational", "advisory")):
        severity = Severity.MEDIUM

    category = "general"
    category_signals = {
        "privacy": ("privacy", "pii", "personal data", "consent", "gdpr"),
        "safety": ("safety", "harm", "danger", "misuse", "abuse"),
        "transparency": ("transparency", "disclose", "explain", "explanation", "audit"),
        "security": ("security", "secret", "credential", "auth", "token"),
    }
    for candidate, signals in category_signals.items():
        if any(signal in desc_lower for signal in signals):
            category = candidate
            break

    resolved_rule_id = rule_id.strip() or "SYNTH-001"
    return {
        "id": resolved_rule_id,
        "text": desc,
        "severity": severity,
        "keywords": _extract_keywords(desc),
        "category": category,
        "workflow_action": ViolationAction.BLOCK if severity.blocks() else ViolationAction.WARN,
    }


class Rule(BaseModel):
    """A single constitutional rule."""

    id: str = Field(..., min_length=1, max_length=50)
    text: str = Field(..., min_length=1, max_length=1000)
    severity: Severity = Severity.HIGH
    keywords: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)
    category: str = "general"
    # exp96: finer-grained classification within a category
    subcategory: str = ""
    # exp99: inter-rule relationships (rule IDs this rule depends on or reinforces)
    depends_on: list[str] = Field(default_factory=list)
    enabled: bool = True
    # exp90: downstream workflow action when this rule fires
    workflow_action: ViolationAction = ViolationAction.BLOCK
    hardcoded: bool = False
    # exp117: arbitrary tags for cross-cutting governance concerns (e.g., "gdpr", "sox", "pci-dss")
    tags: list[str] = Field(default_factory=list)
    # exp124: explicit priority for deterministic ordering within same severity (higher = first)
    priority: int = 0
    # exp129: structured activation condition — rule only applies when context
    # satisfies all entries.
    # Supported operators per key: "equals", "not_equals", "contains", "in", "not_in".
    # Format: {"env": "production"} or {"env": {"op": "in", "value": ["prod", "staging"]}}.
    # Empty dict (default) means unconditional — rule always applies.
    condition: dict[str, Any] = Field(default_factory=dict)
    # exp135: rule lifecycle — deprecated rules remain for audit but are excluded from enforcement.
    # replaced_by: optional rule ID of the successor rule (for migration documentation).
    deprecated: bool = False
    replaced_by: str = ""
    # exp137: temporal validity — ISO-8601 date/datetime strings (e.g., "2025-01-01" or
    # "2025-06-01T00:00:00").  Empty string means unbounded.  Rules with valid_from in the
    # future or valid_until in the past are excluded from active_rules_at() snapshots.
    valid_from: str = ""
    valid_until: str = ""
    # exp138: optional pre-computed embedding vector for semantic similarity search.
    # Empty list means no embedding is set (falls back to Jaccard keyword overlap).
    # Typically generated by an external embedding model (e.g., text-embedding-3-small)
    # and stored alongside the rule for offline semantic search.
    embedding: list[float] = Field(default_factory=list)
    # exp155: rule provenance — list of source rule IDs or external references
    # (e.g., ["GDPR-Art-5", "parent-rule-123"])
    # for tracking rule ancestry and lineage in governance audit trails.
    provenance: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Cached derived values (set in model_post_init, never mutated after)
    _kw_lower: list[str] = []
    _compiled_pats: list[re.Pattern[str]] = []

    @model_validator(mode="before")
    @classmethod
    def default_workflow_action_from_severity(cls, data: Any) -> Any:
        """When workflow_action is absent, derive it from severity.

        CRITICAL/HIGH → BLOCK (severity.blocks() is True).
        MEDIUM/LOW   → WARN  (severity.blocks() is False).

        This preserves the documented Severity semantics:
        ``MEDIUM = "medium"  # Warns but allows``
        while still letting callers explicitly override to BLOCK on any severity.
        """
        if not isinstance(data, dict) or "workflow_action" in data:
            return data
        severity_val = data.get("severity", Severity.HIGH)
        if isinstance(severity_val, str):
            try:
                severity_val = Severity(severity_val)
            except ValueError:
                severity_val = Severity.HIGH
        data["workflow_action"] = (
            ViolationAction.BLOCK if severity_val.blocks() else ViolationAction.WARN
        )
        return data

    @field_validator("workflow_action", mode="before")
    @classmethod
    def coerce_workflow_action(cls, v: Any) -> Any:
        """Coerce empty string (legacy default) to ViolationAction.BLOCK."""
        if v == "" or v is None:
            return ViolationAction.BLOCK
        return v

    @field_validator("patterns")
    @classmethod
    def validate_patterns(cls, v: list[str]) -> list[str]:
        """Ensure regex patterns are valid."""
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{pattern}': {e}") from e
        return v

    @field_validator("valid_from", "valid_until")
    @classmethod
    def validate_temporal_fields(cls, v: str) -> str:
        """Validate ISO-8601 format for temporal validity fields.

        Empty string is allowed (means unbounded). Non-empty values must be
        parseable as ISO-8601 date (``YYYY-MM-DD``) or datetime
        (``YYYY-MM-DDTHH:MM:SS``).
        """
        if not v:
            return v
        try:
            _parse_iso(v)
        except ValueError as e:
            raise ValueError(
                f"Invalid ISO-8601 date/datetime '{v}': {e}. "
                f"Expected format: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS'."
            ) from e
        return v

    def model_post_init(self, __context: Any) -> None:
        """Pre-compute derived values to avoid repeated work per match() call."""
        object.__setattr__(self, "_kw_lower", [k.lower() for k in self.keywords])
        object.__setattr__(
            self,
            "_compiled_pats",
            [re.compile(p, re.IGNORECASE) for p in self.patterns],
        )

    def matches_with_signals(self, text_lower: str, has_neg: bool, has_pos: bool) -> bool:
        """Fast match using pre-computed action-level signals (amortised per validate call).

        Args:
            text_lower: action text already lowercased by the caller.
            has_neg: True if action contains a negative/violation verb.
            has_pos: True if action starts with a positive/constructive verb.
        """
        if not self.enabled:
            return False

        for kw_lower in self._kw_lower:
            if kw_lower in text_lower:
                if has_pos and not has_neg and not _KW_NEGATIVE_RE.search(kw_lower):
                    continue
                return True

        return any(pat.search(text_lower) for pat in self._compiled_pats)

    def match_detail(self, text: str) -> dict[str, Any]:
        """exp93: Return structured match information for governance consumers.

        The ``workflow_action`` value in the returned dict is the string form
        of the :class:`ViolationAction` enum (e.g. ``"block"``), suitable for
        JSON serialisation.

        Unlike ``matches()`` which returns a bare bool, this provides the
        full context needed for governance dashboards, audit trails, and
        downstream workflow routing: which keyword or pattern triggered,
        the rule's severity and workflow_action, and whether positive-verb
        context was detected.

        Args:
            text: The action text to check.

        Returns:
            dict with keys:
                - ``matched``: True if this rule was triggered
                - ``rule_id``: this rule's ID
                - ``severity``: severity level string
                - ``category``: rule category
                - ``workflow_action``: downstream action hint
                - ``trigger_type``: "keyword" | "pattern" | None
                - ``trigger_value``: the specific keyword or pattern that matched
                - ``positive_context``: True if positive verb was detected
        """
        if not self.enabled:
            return {
                "matched": False,
                "rule_id": self.id,
                "severity": self.severity.value,
                "category": self.category,
                "workflow_action": self.workflow_action.value,
                "trigger_type": None,
                "trigger_value": None,
                "positive_context": False,
            }

        text_lower = text.lower()
        has_neg = bool(_NEGATIVE_VERBS_RE.search(text_lower))
        has_pos = (not has_neg) and any(w in _POSITIVE_VERBS_SET for w in text_lower.split()[:4])

        # Check keywords
        for kw_lower in self._kw_lower:
            if kw_lower in text_lower:
                if has_pos and not has_neg and not _KW_NEGATIVE_RE.search(kw_lower):
                    continue
                return {
                    "matched": True,
                    "rule_id": self.id,
                    "severity": self.severity.value,
                    "category": self.category,
                    "workflow_action": self.workflow_action.value,
                    "trigger_type": "keyword",
                    "trigger_value": kw_lower,
                    "positive_context": has_pos,
                }

        # Check patterns
        for pat in self._compiled_pats:
            if m := pat.search(text_lower):
                return {
                    "matched": True,
                    "rule_id": self.id,
                    "severity": self.severity.value,
                    "category": self.category,
                    "workflow_action": self.workflow_action.value,
                    "trigger_type": "pattern",
                    "trigger_value": m.group(0),
                    "positive_context": has_pos,
                }

        return {
            "matched": False,
            "rule_id": self.id,
            "severity": self.severity.value,
            "category": self.category,
            "workflow_action": self.workflow_action.value,
            "trigger_type": None,
            "trigger_value": None,
            "positive_context": has_pos,
        }

    def explain(self) -> dict[str, Any]:
        """exp103: Return a human-readable explanation of this rule.

        Formats rule information for non-technical governance reviewers,
        compliance dashboards, and documentation generators. Includes
        what the rule protects, how it detects violations, and what
        happens when it triggers.

        Returns:
            dict with keys:
                - ``rule_id``: rule identifier
                - ``summary``: one-line human-readable summary
                - ``what_it_protects``: description of the governance concern
                - ``how_it_detects``: description of detection method
                - ``when_triggered``: what happens when the rule fires
                - ``severity_label``: human-readable severity
                - ``dependencies``: list of rules this depends on
        """
        severity_labels = {
            "critical": "Critical — blocks action, no override allowed",
            "high": "High — blocks action, can be overridden with justification",
            "medium": "Medium — warns but allows action to proceed",
            "low": "Low — informational only",
        }

        detection_parts: list[str] = []
        if self.keywords:
            detection_parts.append(
                f"Scans for keywords: {', '.join(repr(k) for k in self.keywords)}"
            )
        if self.patterns:
            detection_parts.append(f"Matches {len(self.patterns)} regex pattern(s)")
        if not detection_parts:
            detection_parts.append("No automatic detection configured")

        workflow_desc = {
            ViolationAction.BLOCK: "Hard block — action is rejected immediately",
            ViolationAction.BLOCK_AND_NOTIFY: "Block and alert the security/compliance team",
            ViolationAction.REQUIRE_HUMAN_REVIEW: "Queue for human review before proceeding",
            ViolationAction.ESCALATE: "Escalate to a senior governance reviewer",
            ViolationAction.WARN: "Log a warning but allow the action",
            ViolationAction.HALT: "Immediate halt — agent circuit-breaker triggered",
        }

        return {
            "rule_id": self.id,
            "summary": f"[{self.severity.value.upper()}] {self.text}",
            "what_it_protects": self.text,
            "how_it_detects": "; ".join(detection_parts),
            "when_triggered": workflow_desc.get(
                self.workflow_action, "No workflow action specified"
            ),
            "severity_label": severity_labels.get(self.severity.value, self.severity.value),
            "dependencies": list(self.depends_on),
        }

    def impact_score(self) -> dict[str, Any]:
        """exp121: Estimate rule governance impact for prioritization and tuning.

        Computes a normalized 0.0-1.0 impact score based on:
        - Severity weight (critical=1.0, high=0.75, medium=0.5, low=0.25)
        - Detection breadth (keyword + pattern count, capped at 10)
        - Configuration richness (workflow_action, tags, dependencies, subcategory)
        - Blocking power (blocking severities score higher)

        Returns:
            dict with keys:
                - ``rule_id``: rule identifier
                - ``score``: normalized impact score (0.0-1.0)
                - ``severity_weight``: contribution from severity
                - ``detection_breadth``: contribution from keywords + patterns
                - ``config_richness``: contribution from configuration completeness
                - ``blocking``: whether this rule blocks execution
                - ``classification``: "high-impact" | "moderate-impact" | "low-impact"
        """
        sev_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.75,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.25,
        }
        sev_w = sev_weights.get(self.severity, 0.5)

        detection_count = len(self.keywords) + len(self.patterns)
        detection_breadth = min(detection_count / 10.0, 1.0)

        config_points = 0.0
        if self.workflow_action:
            config_points += 0.25
        if self.tags:
            config_points += 0.25
        if self.depends_on:
            config_points += 0.25
        if self.subcategory:
            config_points += 0.25

        score = (sev_w * 0.5) + (detection_breadth * 0.3) + (config_points * 0.2)
        score = round(min(score, 1.0), 4)

        if score >= 0.7:
            classification = "high-impact"
        elif score >= 0.4:
            classification = "moderate-impact"
        else:
            classification = "low-impact"

        return {
            "rule_id": self.id,
            "score": score,
            "severity_weight": sev_w,
            "detection_breadth": round(detection_breadth, 4),
            "config_richness": round(config_points, 4),
            "blocking": self.severity.blocks(),
            "classification": classification,
        }

    @classmethod
    def from_description(
        cls,
        description: str,
        *,
        rule_id: str = "",
        llm_provider: RuleSynthesisProvider | None = None,
        default_severity: Severity = Severity.HIGH,
    ) -> Rule:
        """Synthesize a rule from natural-language policy text.

        The ``llm_provider`` is an optional pluggable interface. If omitted,
        ACGS-Lite falls back to deterministic heuristic synthesis so callers can
        use this API in offline/test environments.
        """
        clean_description = description.strip()
        if not clean_description:
            raise ValueError("Rule description cannot be empty")

        payload: dict[str, Any]
        if llm_provider is None:
            payload = _heuristic_rule_payload(
                clean_description,
                rule_id=rule_id,
                default_severity=default_severity,
            )
        else:
            generated = dict(
                llm_provider.generate_rule(
                    clean_description,
                    rule_id=rule_id.strip() or "SYNTH-001",
                )
            )
            payload = _heuristic_rule_payload(
                clean_description,
                rule_id=rule_id,
                default_severity=default_severity,
            )
            payload.update(generated)

        resolved_rule_id = rule_id.strip() or str(payload.get("id", "")).strip()
        if not resolved_rule_id:
            raise ValueError("Synthesized rule payload must include a non-empty 'id'")

        severity_field = payload.get("severity", default_severity)
        if isinstance(severity_field, str):
            severity_value = Severity(severity_field.lower())
        elif isinstance(severity_field, Severity):
            severity_value = severity_field
        else:
            raise TypeError("Synthesized severity must be a str or Severity")

        return cls(
            id=resolved_rule_id,
            text=str(payload.get("text", clean_description)),
            severity=severity_value,
            keywords=[str(k) for k in payload.get("keywords", [])],
            patterns=[str(p) for p in payload.get("patterns", [])],
            category=str(payload.get("category", "general")),
            subcategory=str(payload.get("subcategory", "")),
            depends_on=[str(dep) for dep in payload.get("depends_on", [])],
            enabled=bool(payload.get("enabled", True)),
            workflow_action=payload.get("workflow_action", ViolationAction.BLOCK),
            hardcoded=bool(payload.get("hardcoded", False)),
            tags=[str(t) for t in payload.get("tags", [])],
            priority=int(payload.get("priority", 0)),
            condition=dict(payload.get("condition", {})),
            deprecated=bool(payload.get("deprecated", False)),
            replaced_by=str(payload.get("replaced_by", "")),
            valid_from=str(payload.get("valid_from", "")),
            valid_until=str(payload.get("valid_until", "")),
            embedding=list(payload.get("embedding", [])),
            metadata=dict(payload.get("metadata", {})),
        )

    def condition_matches(self, context: dict[str, Any]) -> bool:
        """exp129: Check whether the rule's activation condition is satisfied.

        An empty condition (default) is unconditional — always returns True.
        Each key in the condition dict is matched against ``context``.

        Supported value formats:
            - scalar: ``{"env": "production"}`` — equality check
            - dict with ``op``: ``{"env": {"op": "in", "value": ["prod", "staging"]}}``
            - dict with fail-closed missing-context behavior:
              ``{"env": {"op": "in", "value": ["prod"], "missing": "match"}}``

        Supported ``op`` values: ``equals``, ``not_equals``, ``contains``,
        ``in``, ``not_in``.

        ``env`` and ``environment`` are treated as aliases. Their string values
        are stripped and lower-cased before comparison.

        Args:
            context: Arbitrary context dict (e.g., from validate() call).

        Returns:
            True if all condition predicates are satisfied (or condition empty).
        """
        if not self.condition:
            return True
        for key, spec in self.condition.items():
            ctx_val = context.get(key)
            if ctx_val is None and key == "env":
                ctx_val = context.get("environment")
            elif ctx_val is None and key == "environment":
                ctx_val = context.get("env")
            if key in {"env", "environment"} and isinstance(ctx_val, str):
                ctx_val = ctx_val.strip().lower()
            if isinstance(spec, dict):
                op = spec.get("op", "equals")
                expected = spec.get("value")
                if ctx_val is None and spec.get("missing") == "match":
                    continue
                if key in {"env", "environment"}:
                    if isinstance(expected, str):
                        expected = expected.strip().lower()
                    elif isinstance(expected, list | tuple | set):
                        expected = [
                            value.strip().lower() if isinstance(value, str) else value
                            for value in expected
                        ]
            else:
                op = "equals"
                expected = spec
                if key in {"env", "environment"} and isinstance(expected, str):
                    expected = expected.strip().lower()
            if (
                op == "equals"
                and ctx_val != expected
                or op == "not_equals"
                and ctx_val == expected
                or op == "contains"
                and (not isinstance(ctx_val, str) or str(expected) not in ctx_val)
                or op == "in"
                and ctx_val not in (expected or [])
                or op == "not_in"
                and ctx_val in (expected or [])
            ):
                return False
        return True

    def matches(self, text: str) -> bool:
        """Check if text matches this rule's patterns or keywords.

        Uses context-aware matching: positive/constructive actions
        (testing, auditing, implementing) are not flagged even if they
        contain governance keywords.

        Returns True if the text triggers this rule (i.e., violates it).
        """
        if not self.enabled:
            return False

        text_lower = text.lower()
        has_neg = bool(_NEGATIVE_VERBS_RE.search(text_lower))
        has_pos = (not has_neg) and any(w in _POSITIVE_VERBS_SET for w in text_lower.split()[:4])
        return self.matches_with_signals(text_lower, has_neg, has_pos)

    def is_valid_at(self, timestamp: str) -> bool:
        """exp137: Return True if this rule is temporally active at *timestamp*.

        *timestamp* must be an ISO-8601 string (date or datetime, e.g.
        ``"2025-06-15"`` or ``"2025-06-15T12:00:00"``).  Rules with an
        empty ``valid_from`` / ``valid_until`` are treated as unbounded on
        that side.

        Boundary behavior: ``valid_until`` is **inclusive** — a rule with
        ``valid_until="2025-12-31"`` is still active at ``"2025-12-31"``
        (midnight).

        Raises :class:`ValueError` if *timestamp* is not a valid ISO-8601
        string (callers should validate inputs).

        Example::

            rule = Rule(id="R1", text="...", valid_from="2025-01-01", valid_until="2025-12-31")
            rule.is_valid_at("2025-06-15")   # → True
            rule.is_valid_at("2024-12-31")   # → False  (before valid_from)
            rule.is_valid_at("2026-01-01")   # → False  (after valid_until)
        """
        ts = _parse_iso(timestamp)

        if self.valid_from and ts < _parse_iso(self.valid_from):
            return False
        return not (self.valid_until and ts > _parse_iso(self.valid_until))

    def cosine_similarity(self, other: Rule) -> float | None:
        """exp138: Cosine similarity between this rule and *other* using stored embeddings.

        Returns a float in [-1.0, 1.0] if both rules have embeddings of the same
        dimensionality, or ``None`` if either embedding is missing/mismatched.

        A similarity of 1.0 indicates identical embedding vectors (semantically equivalent
        rules), 0.0 indicates orthogonal, and negative values indicate semantic opposition.

        Example::

            r1 = Rule(id="R1", text="...", embedding=[0.1, 0.9, 0.3])
            r2 = Rule(id="R2", text="...", embedding=[0.2, 0.8, 0.4])
            r1.cosine_similarity(r2)  # → ~0.996 (highly similar)
        """
        return _cosine_sim(self.embedding, other.embedding)
