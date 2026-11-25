"""Constitution model — a set of rules that govern agent behavior."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field

from . import schema_validation
from .rule import AcknowledgedTension, Rule, Severity, ViolationAction

if TYPE_CHECKING:
    from . import (
        comparison,
        conflict_resolution,
        coverage_analysis,
        dependency_analysis,
        diffing,
        filtering,
        lifecycle,
        merging,
        permission_ceiling,
        provenance,
        regulatory,
        rendering,
        reporting,
        serialization,
        similarity,
        workflow_analytics,
    )
    from .templates import ConstitutionBuilder
else:

    class _LazySubmodule:
        """Import a sibling constitution helper module on first access and bind it."""

        __slots__ = ("_name",)

        def __init__(self, name: str) -> None:
            object.__setattr__(self, "_name", name)

        def _load(self) -> Any:
            name: str = object.__getattribute__(self, "_name")
            mod = importlib.import_module(f".{name}", __package__)
            globals()[name] = mod
            return mod

        def __getattr__(self, attr: str) -> Any:
            return getattr(self._load(), attr)

        def __setattr__(self, attr: str, value: Any) -> None:
            setattr(self._load(), attr, value)

        def __delattr__(self, attr: str) -> None:
            delattr(self._load(), attr)

        def __dir__(self) -> list[str]:
            return dir(self._load())

    comparison = _LazySubmodule("comparison")
    conflict_resolution = _LazySubmodule("conflict_resolution")
    coverage_analysis = _LazySubmodule("coverage_analysis")
    dependency_analysis = _LazySubmodule("dependency_analysis")
    diffing = _LazySubmodule("diffing")
    filtering = _LazySubmodule("filtering")
    lifecycle = _LazySubmodule("lifecycle")
    merging = _LazySubmodule("merging")
    permission_ceiling = _LazySubmodule("permission_ceiling")
    provenance = _LazySubmodule("provenance")
    regulatory = _LazySubmodule("regulatory")
    rendering = _LazySubmodule("rendering")
    reporting = _LazySubmodule("reporting")
    serialization = _LazySubmodule("serialization")
    similarity = _LazySubmodule("similarity")
    workflow_analytics = _LazySubmodule("workflow_analytics")


class Constitution(BaseModel):
    """A set of rules that govern agent behavior."""

    name: str = "default"
    version: str = "1.0.0"
    rules: list[Rule] = Field(default_factory=list)
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    # exp106: rule version history — rule_id → list of snapshots (oldest first)
    rule_history: dict[str, list[Any]] = Field(default_factory=dict)
    # exp128: constitution-level change log (append-only, serialised as dicts)
    changelog: list[dict[str, str]] = Field(default_factory=list)
    # exp147: permission ceiling — advisory policy boundary for downstream
    # (standard | strict | permissive)
    permission_ceiling: str = Field(
        default="standard", description="Policy boundary: standard, strict, or permissive"
    )
    # exp153: optional version label for named snapshots / rollback documentation
    version_name: str = Field(default="", description="Optional label e.g. v1.2 or release-2026-03")

    # Cached values
    _hash_cache: str = ""
    _active_rules_cache: list[Rule] = []

    _DOMAIN_SIGNAL_MAP: dict[str, dict[str, set[str]]] = {
        "safety": {
            "categories": {"safety", "clinical-safety", "operations", "security"},
            "keywords": {"safety", "harm", "abuse", "danger", "oversight", "risk"},
        },
        "privacy": {
            "categories": {"privacy", "data-protection", "compliance"},
            "keywords": {
                "privacy",
                "pii",
                "phi",
                "personal",
                "consent",
                "gdpr",
                "hipaa",
                "confidential",
            },
        },
        "transparency": {
            "categories": {"transparency", "audit", "compliance", "integrity"},
            "keywords": {
                "transparency",
                "disclose",
                "explain",
                "explanation",
                "audit",
                "trace",
                "record",
                "log",
            },
        },
        "fairness": {
            "categories": {"fairness", "compliance", "regulatory"},
            "keywords": {"bias", "fair", "discrimination", "protected", "equal", "adverse action"},
        },
        "accountability": {
            "categories": {"maci", "audit", "integrity", "governance"},
            "keywords": {
                "maci",
                "approve",
                "review",
                "validation",
                "audit",
                "accountability",
                "oversight",
            },
        },
    }

    def model_post_init(self, __context: Any) -> None:
        """Pre-compute hash and active rules cache."""
        # exp160: Validate rule syntax/semantics on constitution load
        validation_errors = self._validate_rules()
        if validation_errors:
            raise ValueError(f"Constitution validation failed: {validation_errors}")

        canonical = "|".join(
            f"{r.id}:{r.text}:{r.severity.value}:{r.hardcoded}:{','.join(sorted(r.keywords))}"
            for r in sorted(self.rules, key=lambda r: r.id)
        )
        h = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        object.__setattr__(self, "_hash_cache", h)
        object.__setattr__(self, "_active_rules_cache", [r for r in self.rules if r.enabled])

    def _validate_rules(self) -> list[str]:
        return schema_validation.validate_rules(self)

    def validate_rules(self) -> list[str]:
        """Validate rule syntax and semantics."""
        return schema_validation.validate_rules(self)

    @property
    def hash(self) -> str:
        """Return the cached constitutional hash."""
        return self._hash_cache

    @property
    def hash_versioned(self) -> str:
        """Return versioned hash string: sha256:v1:<hash>."""
        return f"sha256:v1:{self.hash}"

    @classmethod
    def from_yaml(cls, path: str | Path) -> Constitution:
        """Load a constitution from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Constitution file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)

    @classmethod
    def from_yaml_str(cls, yaml_content: str) -> Constitution:
        """Load a constitution from a YAML string.

        Intended for round-tripping ``Constitution.to_yaml()`` output.
        """
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("YAML content must decode to a mapping/object")
        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Constitution:
        """Create a constitution from a dictionary."""
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Constitution:
        def _coerce_severity(value: Any) -> Severity:
            if isinstance(value, Severity):
                return value
            if isinstance(value, str):
                return Severity(value.strip().lower())
            return Severity(value)

        def _resolve_workflow_action(rule_data: dict[str, Any], severity: Severity) -> Any:
            if "workflow_action" in rule_data:
                return rule_data["workflow_action"]
            return ViolationAction.BLOCK if severity.blocks() else ViolationAction.WARN

        if not isinstance(data, dict):
            raise ValueError("Constitution data must be a mapping/object")
        rules_data = data.get("rules", [])
        if not isinstance(rules_data, list):
            raise ValueError("Constitution 'rules' must be a list of rule objects")
        for index, raw_rule in enumerate(rules_data):
            if not isinstance(raw_rule, dict):
                raise ValueError(f"Constitution rule at index {index} must be a mapping/object")
        rules: list[Rule] = []
        for rule_data in rules_data:
            severity = _coerce_severity(rule_data.get("severity", "high"))
            rules.append(
                Rule(
                    id=rule_data["id"],
                    text=rule_data["text"],
                    severity=severity,
                    keywords=rule_data.get("keywords", []),
                    patterns=rule_data.get("patterns", []),
                    category=rule_data.get("category", "general"),
                    subcategory=rule_data.get("subcategory", ""),
                    depends_on=rule_data.get("depends_on", []),
                    enabled=rule_data.get("enabled", True),
                    workflow_action=_resolve_workflow_action(rule_data, severity),
                    hardcoded=rule_data.get("hardcoded", False),
                    tags=rule_data.get("tags", []),
                    priority=int(rule_data.get("priority", 0)),
                    condition=dict(rule_data.get("condition", {})),
                    deprecated=bool(rule_data.get("deprecated", False)),
                    replaced_by=str(rule_data.get("replaced_by", "")),
                    valid_from=str(rule_data.get("valid_from", "")),
                    valid_until=str(rule_data.get("valid_until", "")),
                    embedding=list(rule_data.get("embedding", [])),
                    provenance=list(rule_data.get("provenance", [])),
                    metadata=rule_data.get("metadata", {}),
                )
            )
        return cls(
            name=data.get("name", "default"),
            version=data.get("version", "1.0.0"),
            rules=rules,
            description=data.get("description", ""),
            metadata=data.get("metadata", {}),
            permission_ceiling=str(data.get("permission_ceiling", "standard")).lower(),
            version_name=str(data.get("version_name", "")),
        )

    @classmethod
    def from_rules(cls, rules: Sequence[Rule], name: str = "custom") -> Constitution:
        """Create a constitution from a list of Rule objects."""
        return cls(name=name, rules=list(rules))

    @classmethod
    def default(cls) -> Constitution:
        """Return the ACGS default constitution with core safety rules."""
        return cls(
            name="acgs-default",
            version="1.0.0",
            description="ACGS default constitutional rules for AI agent governance",
            rules=[
                Rule(
                    id="ACGS-001",
                    text="Agents must not modify their own validation logic",
                    severity=Severity.CRITICAL,
                    keywords=["self-validate", "bypass validation", "skip check"],
                    category="integrity",
                    subcategory="self-modification",
                    workflow_action=ViolationAction.BLOCK,
                    tags=["compliance", "eu-ai-act"],
                ),
                Rule(
                    id="ACGS-002",
                    text="All actions must produce an audit trail entry",
                    severity=Severity.HIGH,
                    keywords=["no-audit", "skip audit", "disable logging"],
                    category="audit",
                    subcategory="trail-completeness",
                    workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
                    tags=["compliance", "sox", "eu-ai-act"],
                ),
                Rule(
                    id="ACGS-003",
                    text="Agents must not access data outside their authorized scope",
                    severity=Severity.CRITICAL,
                    keywords=["unauthorized", "escalate privilege", "admin override"],
                    category="access",
                    subcategory="scope-violation",
                    depends_on=["ACGS-002"],  # scope violations must be audited
                    workflow_action=ViolationAction.BLOCK,
                    tags=["compliance", "gdpr", "eu-ai-act"],
                ),
                Rule(
                    id="ACGS-004",
                    text="Proposers cannot validate their own proposals (MACI)",
                    severity=Severity.CRITICAL,
                    keywords=["self-approve", "auto-approve"],
                    category="maci",
                    subcategory="separation-of-powers",
                    depends_on=["ACGS-001"],  # self-validation is a form of self-modification
                    workflow_action=ViolationAction.BLOCK,
                    tags=["compliance", "eu-ai-act"],
                ),
                Rule(
                    id="ACGS-005",
                    text="All governance changes require constitutional hash verification",
                    severity=Severity.HIGH,
                    keywords=["skip hash", "ignore constitution"],
                    category="integrity",
                    subcategory="hash-verification",
                    depends_on=["ACGS-001"],  # hash bypass is a form of validation bypass
                    workflow_action=ViolationAction.REQUIRE_HUMAN_REVIEW,
                    tags=["compliance", "eu-ai-act"],
                ),
                Rule(
                    id="ACGS-006",
                    text="Agents must not expose sensitive data in responses",
                    severity=Severity.CRITICAL,
                    keywords=["password", "secret key", "api_key", "private key"],
                    patterns=[
                        r"(?i)(sk-[a-zA-Z0-9]{20,})",
                        r"(?i)(ghp_[a-zA-Z0-9]{36})",
                        r"\b\d{3}-\d{2}-\d{4}\b",
                    ],
                    category="data-protection",
                    subcategory="credential-exposure",
                    workflow_action=ViolationAction.BLOCK_AND_NOTIFY,
                    tags=["gdpr", "pci-dss", "hipaa"],
                ),
            ],
        )

    @classmethod
    def from_template(cls, domain: str) -> Constitution:
        """exp105: Return a pre-built constitution for a well-known governance domain.

        Lowers the barrier to adoption by providing ready-to-use constitutions for
        common AI deployment scenarios. Each template captures the most impactful
        rules for that domain — useful for GitLab CI/CD gates, healthcare AI,
        financial AI, and security-sensitive deployments.

        Args:
            domain: One of "gitlab", "healthcare", "finance", "security", "general".

        Returns:
            A Constitution pre-populated with domain-appropriate rules.

        Raises:
            ValueError: If the domain is not recognised.

        Example::

            constitution = Constitution.from_template("gitlab")
            engine = GovernanceEngine(constitution)
            result = engine.validate("auto-approve merge request", agent_id="ci-bot")
        """
        from .template_data import TEMPLATES as _TEMPLATES

        domain_lower = domain.lower().strip()
        if domain_lower not in _TEMPLATES:
            available = ", ".join(sorted(_TEMPLATES.keys()))
            raise ValueError(f"Unknown governance domain {domain!r}. Available: {available}")
        return cls.from_dict(_TEMPLATES[domain_lower])

    def update_rule(
        self,
        rule_id: str,
        *,
        change_reason: str = "",
        **changes: Any,
    ) -> Constitution:
        """exp106: Return a new Constitution with the specified rule updated.

        Captures a ``RuleSnapshot`` of the current rule state before applying
        changes, then appends it to ``rule_history``. The returned Constitution
        is a fresh object with a new hash reflecting the updated rules.

        Immutable pattern: never modifies self. Returns a new Constitution.

        Args:
            rule_id: ID of the rule to update.
            change_reason: Human-readable description of why this change was made.
            **changes: Rule field values to update (text, severity, enabled,
                keywords, patterns, category, subcategory, workflow_action).

        Returns:
            New Constitution with the rule updated and history appended.

        Raises:
            KeyError: If rule_id is not found in this constitution.

        Example::

            c2 = constitution.update_rule(
                "GL-001",
                severity="critical",
                change_reason="Escalated after incident 2026-Q1-007",
            )
            print(c2.rule_changelog("GL-001"))
        """
        existing = self.get_rule(rule_id)
        if existing is None:
            raise KeyError(f"Rule {rule_id!r} not found in constitution {self.name!r}")

        # Determine current version number from history
        current_history = list(self.rule_history.get(rule_id, []))
        next_version = len(current_history) + 1

        # Snapshot the current state before changing it
        from .versioning import RuleSnapshot

        snapshot = RuleSnapshot.from_rule(
            existing, version=next_version, change_reason=change_reason
        )
        new_history = {**self.rule_history, rule_id: [*current_history, snapshot]}

        # Coerce severity string → Severity enum if needed
        if "severity" in changes and isinstance(changes["severity"], str):
            changes = {**changes, "severity": Severity(changes["severity"])}

        # Build updated rule using Rule constructor to trigger validation
        updated_data = existing.model_dump()
        updated_data.update(changes)
        updated_rule = Rule(**updated_data)

        # Rebuild rules list
        new_rules = [updated_rule if r.id == rule_id else r for r in self.rules]

        # exp128: append changelog entry (inline dict, no extra import needed)
        ts = datetime.now(timezone.utc).isoformat()
        new_changelog = [
            *self.changelog,
            {
                "operation": "update_rule",
                "rule_id": rule_id,
                "timestamp": ts,
                "reason": change_reason,
                "actor": "",
            },
        ]

        return Constitution(
            name=self.name,
            version=self.version,
            description=self.description,
            rules=new_rules,
            metadata=self.metadata,
            rule_history=new_history,
            changelog=new_changelog,
        )

    def rule_changelog(self, rule_id: str) -> list[dict[str, Any]]:
        """exp106: Return human-readable change log for a rule.

        Returns a list of snapshot dicts (oldest first), each describing
        the rule state at that version and the reason for the change.

        Args:
            rule_id: ID of the rule to inspect.

        Returns:
            List of snapshot dicts (see ``RuleSnapshot.to_dict()``).
            Returns empty list if the rule has no recorded history.
        """
        return [snap.to_dict() for snap in self.rule_history.get(rule_id, [])]

    def rule_version(self, rule_id: str) -> int:
        """exp106: Return the current version number of a rule.

        Version 1 = original (no history), 2 = one update, etc.

        Args:
            rule_id: ID of the rule to query.

        Returns:
            Current version number (always >= 1).
        """
        return len(self.rule_history.get(rule_id, [])) + 1

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """exp119: Return a JSON Schema describing valid constitution YAML/JSON.

        Use this schema in CI/CD pipelines to validate constitution files before
        deployment. The schema enforces required fields, valid enum values, and
        structural constraints.

        Returns:
            JSON Schema dict (draft 2020-12 compatible).

        Example::

            import json
            schema = Constitution.json_schema()
            with open("constitution-schema.json", "w") as f:
                json.dump(schema, f, indent=2)
        """
        rule_schema: dict[str, Any] = {
            "type": "object",
            "required": ["id", "text"],
            "properties": {
                "id": {"type": "string", "minLength": 1, "maxLength": 50},
                "text": {"type": "string", "minLength": 1, "maxLength": 1000},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "default": "high",
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "category": {"type": "string", "default": "general"},
                "subcategory": {"type": "string", "default": ""},
                "depends_on": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "enabled": {"type": "boolean", "default": True},
                "workflow_action": {
                    "type": "string",
                    "enum": [
                        "",
                        "block",
                        "block_and_notify",
                        "require_human_review",
                        "escalate_to_senior",
                        "warn",
                    ],
                    "default": "",
                },
                "hardcoded": {"type": "boolean", "default": False},
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "metadata": {"type": "object", "default": {}},
            },
            "additionalProperties": False,
        }

        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ACGS Constitution",
            "description": "Schema for ACGS constitutional governance YAML/JSON files.",
            "type": "object",
            "required": ["rules"],
            "properties": {
                "name": {"type": "string", "default": "default"},
                "version": {"type": "string", "default": "1.0.0"},
                "description": {"type": "string", "default": ""},
                "rules": {
                    "type": "array",
                    "items": rule_schema,
                    "minItems": 1,
                },
                "metadata": {"type": "object", "default": {}},
            },
            "additionalProperties": False,
        }

    @staticmethod
    def validate_yaml_schema(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        return schema_validation.validate_yaml_schema(data)

    @classmethod
    def inherit(
        cls,
        parent: Constitution,
        child: Constitution,
        *,
        override_strategy: str = "child_wins",
    ) -> Constitution:
        return merging.inherit(parent, child, override_strategy=override_strategy)

    def apply_amendments(self, amendments: Sequence[Any]) -> Constitution:
        """Apply a sequence of amendment-like payloads to this constitution."""
        return merging.apply_amendments(self, amendments)

    def apply_amendments_with_report(
        self,
        amendments: Sequence[Any],
    ) -> tuple[Constitution, Any]:
        """Apply amendments and return a review artifact for the change."""
        return merging.apply_amendments_with_report(self, amendments)

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the constitution and invalidate caches."""
        self.rules.append(rule)
        self._rebuild_caches()

    def replace_rule(self, rule_id: str, updated: Rule) -> None:
        """Replace a rule by ID and invalidate caches."""
        self.rules = [updated if r.id == rule_id else r for r in self.rules]
        self._rebuild_caches()

    def remove_rule(self, rule_id: str) -> None:
        """Remove a rule by ID and invalidate caches."""
        self.rules = [r for r in self.rules if r.id != rule_id]
        self._rebuild_caches()

    def _rebuild_caches(self) -> None:
        """Invalidate hash and active rules caches after mutation."""
        object.__setattr__(self, "_hash_cache", "")
        object.__setattr__(self, "_active_rules_cache", [r for r in self.rules if r.enabled])
        # Force hash recomputation
        _ = self.hash

    def active_rules(self) -> list[Rule]:
        """Return only enabled rules (cached)."""
        return self._active_rules_cache

    def deprecated_rules(self) -> list[Rule]:
        """exp135: Return all deprecated rules regardless of enabled state.

        Deprecated rules are retained in the constitution for audit-trail
        continuity but excluded from active enforcement by
        :meth:`active_non_deprecated`.  Each entry includes its
        ``replaced_by`` pointer (if set) to support migration documentation.

        Returns:
            List of :class:`Rule` objects where ``deprecated=True``.
        """
        return [r for r in self.rules if r.deprecated]

    def active_non_deprecated(self) -> list[Rule]:
        """exp135: Return enabled, non-deprecated rules for enforcement.

        Stricter than :meth:`active_rules` — excludes rules that are enabled
        but have been marked deprecated.  Use this in runtime governance
        pipelines to avoid enforcing obsolete rules while the ``enabled``
        flag migration is in progress.

        Returns:
            List of enabled :class:`Rule` objects where ``deprecated=False``.
        """
        return [r for r in self.active_rules() if not r.deprecated]

    def active_rules_at(self, timestamp: str) -> list[Rule]:
        """exp137: Return enabled rules that are temporally valid at *timestamp*.

        Combines :meth:`active_non_deprecated` filtering with temporal
        validity so callers can snapshot the governance posture at any
        point in time — e.g., for compliance audits, back-testing, or
        scheduled policy activation.

        *timestamp* should be an ISO-8601 string such as ``"2025-06-15"``
        or ``"2025-06-15T12:00:00"``.  Rules with no ``valid_from`` /
        ``valid_until`` set are always included (unbounded).

        Example::

            # Rules valid during Q1 2025
            q1_rules = constitution.active_rules_at("2025-03-01")

            # Schedule a rule to activate on 2026-01-01
            future_rule = Rule(
                id="GDPR-2026",
                text="Enhanced data retention enforcement",
                valid_from="2026-01-01",
                keywords=["data retention"],
            )

        Returns:
            List of enabled, non-deprecated :class:`Rule` objects whose
            temporal window includes *timestamp*.
        """
        return [r for r in self.active_non_deprecated() if r.is_valid_at(timestamp)]

    def deprecation_report(self) -> dict[str, Any]:
        """Deprecation status summary. See :mod:`lifecycle`."""
        return lifecycle.deprecation_report(self)

    def deprecation_migration_report(self) -> dict[str, Any]:
        """Per-rule migration guidance for deprecated rules. See :mod:`lifecycle`."""
        return lifecycle.deprecation_migration_report(self)

    def rule_provenance_graph(self) -> dict[str, Any]:
        return provenance.rule_provenance_graph(self)

    def active_rules_for_context(self, context: dict[str, Any]) -> list[Rule]:
        """exp129: Return enabled rules whose activation conditions match context.

        Filters :meth:`active_rules` through each rule's ``condition`` predicate.
        Rules with an empty condition (default) are always included.
        Rules with a condition are included only if their condition is satisfied
        by the provided context dict.

        This enables context-gated governance: a rule with
        ``condition={"env": "production"}`` will only fire in production
        deployments, reducing noise in development/staging environments.

        Args:
            context: Arbitrary context dict, e.g. ``{"env": "production",
                "tier": "admin"}``.

        Returns:
            List of :class:`Rule` objects that are both enabled and whose
            conditions are satisfied by *context*.

        Example::

            prod_rules = constitution.active_rules_for_context({"env": "production"})
            dev_rules = constitution.active_rules_for_context({"env": "dev"})
            # dev_rules will exclude production-only rules
        """
        return [r for r in self.active_rules() if r.condition_matches(context)]

    def explain(self, action: str) -> dict[str, Any]:
        """exp118: Human-readable explanation of a governance decision.

        Evaluates *action* against all active rules and returns a structured
        explanation of the decision: whether the action is allowed or denied,
        which rules triggered (with matched keywords/patterns), and a
        human-readable summary suitable for audit logs, dashboards, or
        end-user feedback.

        Args:
            action: The action text to evaluate.

        Returns:
            dict with keys:
                - ``action``: the evaluated action text
                - ``decision``: "allow" | "deny"
                - ``triggered_rules``: list of match_detail dicts for rules that fired
                - ``blocking_rules``: subset of triggered_rules with blocking severity
                - ``warning_rules``: subset of triggered_rules with non-blocking severity
                - ``tags_involved``: deduplicated tags from all triggered rules
                - ``explanation``: human-readable summary string
                - ``recommendation``: suggested next step

        Example::

            result = constitution.explain("bypass validation and self-approve")
            print(result["explanation"])
            # "Action DENIED by 2 rules: ACGS-001 (critical: keyword 'bypass validation'),
            #  ACGS-004 (critical: keyword 'self-approve'). Tags: compliance, eu-ai-act."
        """
        triggered = []
        for r in self.active_rules():
            detail = r.match_detail(action)
            if detail["matched"]:
                detail["tags"] = list(r.tags)
                detail["rule_text"] = r.text
                triggered.append(detail)

        blocking = [t for t in triggered if Severity(t["severity"]).blocks()]
        warnings = [t for t in triggered if not Severity(t["severity"]).blocks()]
        decision = "deny" if blocking else "allow"

        all_tags: list[str] = []
        seen_tags: set[str] = set()
        for t in triggered:
            for tag in t.get("tags", []):
                if tag not in seen_tags:
                    all_tags.append(tag)
                    seen_tags.add(tag)

        # Build human-readable explanation
        if not triggered:
            explanation = "Action ALLOWED — no rules triggered."
            recommendation = "No action required."
        elif blocking:
            parts = []
            for t in blocking:
                trigger = (
                    f"{t['trigger_type']} '{t['trigger_value']}'" if t["trigger_value"] else "match"
                )
                parts.append(f"{t['rule_id']} ({t['severity']}: {trigger})")
            explanation = f"Action DENIED by {len(blocking)} rule(s): {', '.join(parts)}."
            if warnings:
                explanation += f" Additionally, {len(warnings)} warning(s) raised."
            if all_tags:
                explanation += f" Tags: {', '.join(all_tags)}."
            recommendation = (
                "Review the action for compliance. "
                "Blocking rules require remediation before the action can proceed."
            )
        else:
            parts = []
            for t in warnings:
                trigger = (
                    f"{t['trigger_type']} '{t['trigger_value']}'" if t["trigger_value"] else "match"
                )
                parts.append(f"{t['rule_id']} ({t['severity']}: {trigger})")
            explanation = f"Action ALLOWED with {len(warnings)} warning(s): {', '.join(parts)}."
            if all_tags:
                explanation += f" Tags: {', '.join(all_tags)}."
            recommendation = "Warnings are informational. Consider reviewing flagged concerns."

        return {
            "action": action,
            "decision": decision,
            "triggered_rules": triggered,
            "blocking_rules": blocking,
            "warning_rules": warnings,
            "tags_involved": all_tags,
            "explanation": explanation,
            "recommendation": recommendation,
        }

    def compare(
        self,
        other: Constitution,
    ) -> dict[str, Any]:
        """Compare two constitutions and return structured differences."""
        return diffing.compare(self, other)

    def diff_summary(self, other: Constitution) -> str:
        """Return a concise human-readable summary of constitution changes."""
        return diffing.diff_summary(self, other)

    def governance_summary(self) -> dict[str, Any]:
        return workflow_analytics.analyze_workflow_distribution(self)

    def analyze_workflow_distribution(self) -> dict[str, Any]:
        """Return workflow distribution analytics for this constitution."""
        return workflow_analytics.analyze_workflow_distribution(self)

    def validate_integrity(self) -> dict[str, Any]:
        """Structural consistency checks. See :mod:`dependency_analysis`."""
        return dependency_analysis.validate_integrity(self)

    @staticmethod
    def subsumes(
        superset: Constitution,
        subset: Constitution,
    ) -> dict[str, Any]:
        """Check whether one constitution fully subsumes another. See :mod:`comparison`."""
        return comparison.subsumes(superset, subset)

    def counterfactual(
        self,
        action: str,
        *,
        remove_rules: Sequence[str] | None = None,
        context: dict[str, Any] | None = None,
        agent_id: str = "counterfactual",
    ) -> dict[str, Any]:
        """Evaluate how removing rules would change a decision. See :mod:`comparison`."""
        return comparison.counterfactual(
            self,
            action,
            remove_rules=remove_rules,
            context=context,
            agent_id=agent_id,
        )

    def dependency_graph(self) -> dict[str, Any]:
        """Inter-rule dependency graph (edges, roots, orphans). See :mod:`dependency_analysis`."""
        return dependency_analysis.dependency_graph(self)

    def rule_dependencies(self) -> dict[str, Any]:
        """Implicit semantic dependency analysis. See :mod:`dependency_analysis`."""
        return dependency_analysis.rule_dependencies(self)

    def resolve_conflicts(self, conflicts: list[dict[str, Any]]) -> dict[str, Any]:
        return conflict_resolution.resolve_conflicts(self, conflicts)

    def merge_constitutions(self, other: Constitution, strategy: str = "union") -> Constitution:
        return merging.merge_constitutions(self, other, strategy=strategy)

    @staticmethod
    def create_rule_from_template(
        template_name: str, rule_id: str, parameters: dict[str, Any]
    ) -> Rule:
        """exp162: Create a rule from a predefined template.

        Provides reusable patterns for common governance scenarios,
        reducing boilerplate and ensuring consistency.

        Args:
            template_name: Name of the template to use
            rule_id: Unique ID for the new rule
            parameters: Template parameters

        Returns:
            New Rule instance

        Raises:
            ValueError: If template_name is unknown or parameters are invalid
        """
        templates = {
            "data_privacy": {
                "text": "Prohibit {action} of {data_type} data without {consent_type} consent",
                "severity": "high",
                "keywords": ["{data_type}", "privacy", "consent", "{action}"],
                "category": "privacy",
            },
            "security_boundary": {
                "text": (
                    "Block {action} across {boundary_type} boundaries"
                    " without explicit authorization"
                ),
                "severity": "critical",
                "keywords": ["{boundary_type}", "security", "boundary", "{action}"],
                "category": "security",
            },
            "compliance_audit": {
                "text": (
                    "Require audit logging for all {action} operations involving {asset_type}"
                ),
                "severity": "medium",
                "keywords": ["{asset_type}", "audit", "compliance", "{action}", "logging"],
                "category": "compliance",
            },
            "resource_limit": {
                "text": (
                    "Limit {resource_type} usage to {limit} per {time_period} for {user_type} users"
                ),
                "severity": "low",
                "keywords": ["{resource_type}", "limit", "{limit}", "{user_type}"],
                "category": "operations",
            },
            "access_control": {
                "text": (
                    "Require {auth_method} authentication for {action} access to {resource_type}"
                ),
                "severity": "high",
                "keywords": [
                    "{resource_type}",
                    "access",
                    "authentication",
                    "{auth_method}",
                    "{action}",
                ],
                "category": "security",
            },
        }

        if template_name not in templates:
            raise ValueError(
                f"Unknown template: {template_name}. Available: {list(templates.keys())}"
            )

        template = templates[template_name]

        # Fill in template parameters
        text: str = str(template["text"])
        keywords = []
        for param in parameters:
            text = text.replace(f"{{{param}}}", str(parameters[param]))
            if param in template["keywords"]:
                keywords.extend(str(parameters[param]).split())

        # Add fixed keywords
        for kw in template["keywords"]:
            if not kw.startswith("{"):
                keywords.append(kw)

        return Rule(
            id=rule_id,
            text=text,
            severity=Severity(template["severity"]),
            keywords=list(set(keywords)),  # deduplicate
            category=str(template["category"]),
            enabled=True,
            hardcoded=False,
            metadata={"template": template_name, "template_params": parameters},
        )

    def diff(self, other: Constitution) -> dict[str, Any]:
        """Structured diff between two constitutions. See :mod:`comparison`."""
        return comparison.diff(self, other)

    def get_governance_metrics(self) -> dict[str, Any]:
        """Real-time governance performance metrics dashboard. See :mod:`reporting`."""
        return reporting.get_governance_metrics(self)

    def merge(
        self,
        other: Constitution,
        *,
        strategy: str = "keep_higher_severity",
        name: str = "",
        acknowledged_tensions: Sequence[AcknowledgedTension] | None = None,
        allow_hardcoded_override: bool = False,
    ) -> dict[str, Any]:
        """Merge two constitutions with conflict detection and resolution. See :mod:`merging`."""
        return merging.merge(
            self,
            other,
            strategy=strategy,
            name=name,
            acknowledged_tensions=acknowledged_tensions,
            allow_hardcoded_override=allow_hardcoded_override,
        )

    def set_rule_lifecycle_state(self, rule_id: str, state: str, reason: str = "") -> bool:
        """Set lifecycle state (draft/active/deprecated) for a rule. See :mod:`lifecycle`."""
        return lifecycle.set_rule_lifecycle_state(self, rule_id, state, reason)

    def get_rule_lifecycle_states(self) -> dict[str, dict[str, Any]]:
        """Return lifecycle state summary for all rules. See :mod:`lifecycle`."""
        return lifecycle.get_rule_lifecycle_states(self)

    def lifecycle_transition_rules(self, from_state: str, to_state: str) -> list[str]:
        """Find rules eligible for a lifecycle state transition. See :mod:`lifecycle`."""
        return lifecycle.lifecycle_transition_rules(self, from_state, to_state)

    def cascade(self, child: Constitution, *, name: str = "") -> Constitution:
        """Parent-authoritative federation of two constitutions. See :mod:`merging`."""
        return merging.cascade(self, child, name=name)

    def set_rule_tenants(self, rule_id: str, tenants: list[str]) -> bool:
        """Assign tenant scoping to a rule. See :mod:`lifecycle`."""
        return lifecycle.set_rule_tenants(self, rule_id, tenants)

    def get_tenant_rules(self, tenant_id: str | None = None) -> list[Rule]:
        """Filter rules by tenant ID. See :mod:`lifecycle`."""
        return lifecycle.get_tenant_rules(self, tenant_id)

    def tenant_isolation_report(self) -> dict[str, Any]:
        """Tenant isolation statistics and conflict detection. See :mod:`lifecycle`."""
        return lifecycle.tenant_isolation_report(self)

    def detect_conflicts(self) -> dict[str, Any]:
        """exp110: Detect rules with overlapping triggers but conflicting actions.

        Finds pairs of rules that share keywords or patterns but differ in
        severity or workflow_action. These conflicts can cause unpredictable
        governance outcomes and should be reviewed before deployment.

        Complements ``validate_integrity()`` (structural checks) by detecting
        *semantic* conflicts — rules that are individually valid but
        collectively contradictory.

        Returns:
            dict with keys:
                - ``has_conflicts``: True if any conflicts detected
                - ``conflicts``: list of dicts, each with ``rule_a``, ``rule_b``,
                  ``shared_keywords``, ``severity_conflict``, ``workflow_conflict``
                - ``conflict_count``: total number of conflicting pairs
                - ``recommendation``: summary suggestion for resolution

        Example::

            report = constitution.detect_conflicts()
            if report["has_conflicts"]:
                for c in report["conflicts"]:
                    print(f"{c['rule_a']} vs {c['rule_b']}: "
                          f"shared={c['shared_keywords']}")
        """
        active = self.active_rules()
        # Build keyword→rule_ids index
        kw_index: dict[str, list[str]] = {}
        rule_kws: dict[str, set[str]] = {}
        rule_map: dict[str, Rule] = {}

        for r in active:
            rule_map[r.id] = r
            lower_kws = {kw.lower() for kw in r.keywords}
            rule_kws[r.id] = lower_kws
            for kw in lower_kws:
                kw_index.setdefault(kw, []).append(r.id)

        # Find rule pairs sharing keywords
        checked: set[tuple[str, str]] = set()
        conflicts: list[dict[str, Any]] = []

        for _kw, rule_ids in kw_index.items():
            if len(rule_ids) < 2:
                continue
            for i, rid_a in enumerate(rule_ids):
                for rid_b in rule_ids[i + 1 :]:
                    pair = (min(rid_a, rid_b), max(rid_a, rid_b))
                    if pair in checked:
                        continue
                    checked.add(pair)

                    ra = rule_map[rid_a]
                    rb = rule_map[rid_b]
                    shared = sorted(rule_kws[rid_a] & rule_kws[rid_b])

                    sev_conflict = ra.severity != rb.severity
                    wf_conflict = ra.workflow_action != rb.workflow_action

                    if sev_conflict or wf_conflict:
                        conflict_entry: dict[str, Any] = {
                            "rule_a": rid_a,
                            "rule_b": rid_b,
                            "shared_keywords": shared,
                            "severity_conflict": sev_conflict,
                            "workflow_conflict": wf_conflict,
                        }
                        if sev_conflict:
                            conflict_entry["severity_a"] = ra.severity.value
                            conflict_entry["severity_b"] = rb.severity.value
                        if wf_conflict:
                            conflict_entry["workflow_a"] = ra.workflow_action.value
                            conflict_entry["workflow_b"] = rb.workflow_action.value
                        conflicts.append(conflict_entry)

        recommendation = ""
        if conflicts:
            recommendation = (
                f"Found {len(conflicts)} conflicting rule pair(s). "
                "Review shared keywords and align severity/workflow_action, "
                "or add subcategory distinctions to differentiate intent."
            )

        return {
            "has_conflicts": len(conflicts) > 0,
            "conflicts": conflicts,
            "conflict_count": len(conflicts),
            "recommendation": recommendation,
        }

    def detect_semantic_conflicts(self, threshold: float = 0.8) -> dict[str, Any]:
        return conflict_resolution.detect_semantic_conflicts(self, threshold=threshold)

    def provenance_graph(self) -> dict[str, Any]:
        return provenance.provenance_graph(self)

    def to_yaml(self) -> str:
        """Serialize constitution to YAML string. See :mod:`serialization`."""
        return serialization.to_yaml(self)

    def to_bundle(self) -> dict[str, Any]:
        """Export constitution as a JSON-serializable bundle. See :mod:`serialization`."""
        return serialization.to_bundle(self)

    def to_response_schema(self, *, strict: bool = False) -> dict[str, Any]:
        """Export as a JSON Schema for constrained LLM output."""
        from acgs_lite.constitution.response_schema import constitution_to_response_schema

        return constitution_to_response_schema(self, strict=strict)

    def to_rego(self, package_name: str = "acgs.governance") -> str:
        """Export constitution as OPA Rego policy. See :mod:`serialization`."""
        return serialization.to_rego(self, package_name=package_name)

    @classmethod
    def from_bundle(cls, bundle: dict[str, Any]) -> Constitution:
        """Reconstruct constitution from a bundle dict. See :mod:`serialization`."""
        return serialization.from_bundle(bundle)

    def regulatory_alignment(
        self,
        framework: str = "soc2",
    ) -> dict[str, Any]:
        return regulatory.regulatory_alignment(self, framework=framework)

    def find_similar_rules(
        self,
        *,
        threshold: float = 0.7,
        include_disabled: bool = False,
    ) -> list[dict[str, Any]]:
        """Find near-duplicate rules by Jaccard keyword overlap. See :mod:`similarity`."""
        return similarity.find_similar_rules(
            self,
            threshold=threshold,
            include_disabled=include_disabled,
        )

    def cosine_similar_rules(
        self,
        threshold: float = 0.8,
        min_dim: int = 4,
    ) -> list[dict[str, Any]]:
        """Find similar rules by cosine similarity. See :mod:`similarity`."""
        return similarity.cosine_similar_rules(self, threshold=threshold, min_dim=min_dim)

    def semantic_search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Retrieve rules by embedding similarity. See :mod:`similarity`."""
        return similarity.semantic_search(
            self,
            query_embedding=query_embedding,
            top_k=top_k,
            threshold=threshold,
        )

    def full_report(
        self,
        *,
        regulatory_framework: str = "soc2",
        similarity_threshold: float = 0.7,
        include_similar_rules: bool = True,
    ) -> dict[str, Any]:
        """Comprehensive governance report. See :mod:`reporting`."""
        return reporting.full_report(
            self,
            regulatory_framework=regulatory_framework,
            similarity_threshold=similarity_threshold,
            include_similar_rules=include_similar_rules,
        )

    def compliance_report(self, *, framework: str = "soc2") -> dict[str, Any]:
        """Regulatory-focused compliance report for audit consumers. See :mod:`reporting`."""
        return reporting.compliance_report(self, framework=framework)

    @staticmethod
    def assess_decision_anomaly(
        allow_count: int = 0,
        deny_count: int = 0,
        escalate_count: int = 0,
        *,
        baseline_deny_rate: float = 0.15,
        baseline_escalate_rate: float = 0.10,
        spike_threshold: float = 2.0,
    ) -> dict[str, Any]:
        """exp146: Statistical anomaly detection on governance decision distributions.

        Accepts counts of allow/deny/escalate outcomes (e.g. from
        GovernanceMetrics.snapshot() or an audit log) and returns the
        observed distribution plus signals when rates diverge from
        expected baselines.  Intended for dashboards and alerting when
        deny or escalate rates spike relative to historical norms.

        Does not touch the validation hot path; callers supply pre-aggregated
        counts from their own metrics or audit store.

        Args:
            allow_count: Number of allowed decisions in the window.
            deny_count: Number of denied decisions in the window.
            escalate_count: Number of escalated decisions in the window.
            baseline_deny_rate: Expected deny rate (0.0-1.0). Default 0.15.
            baseline_escalate_rate: Expected escalate rate (0.0-1.0). Default 0.10.
            spike_threshold: Factor above baseline to flag as spike (e.g. 2.0 =
                twice the baseline rate). Default 2.0.

        Returns:
            dict with keys:

            - ``total``: total decisions
            - ``distribution``: allow_rate, deny_rate, escalate_rate (0-1)
            - ``rates``: same as distribution (alias)
            - ``anomalies``: list of detected signals (e.g. high_deny_rate,
              high_escalate_rate)
            - ``is_anomalous``: True if any anomaly signal was raised
            - ``baseline_deny_rate``, ``baseline_escalate_rate``: echo of inputs

        Example::

            snap = metrics.snapshot()
            r = Constitution.assess_decision_anomaly(
                snap["allow_count"], snap["deny_count"], snap["escalate_count"],
                baseline_deny_rate=0.1,
            )
            if r["is_anomalous"]:
                alert(r["anomalies"])
        """
        total = allow_count + deny_count + escalate_count
        if total == 0:
            return {
                "total": 0,
                "distribution": {"allow_rate": 0.0, "deny_rate": 0.0, "escalate_rate": 0.0},
                "rates": {"allow_rate": 0.0, "deny_rate": 0.0, "escalate_rate": 0.0},
                "anomalies": [],
                "is_anomalous": False,
                "baseline_deny_rate": baseline_deny_rate,
                "baseline_escalate_rate": baseline_escalate_rate,
            }

        allow_rate = allow_count / total
        deny_rate = deny_count / total
        escalate_rate = escalate_count / total
        distribution = {
            "allow_rate": round(allow_rate, 4),
            "deny_rate": round(deny_rate, 4),
            "escalate_rate": round(escalate_rate, 4),
        }
        anomalies: list[str] = []

        if baseline_deny_rate > 0 and deny_rate >= baseline_deny_rate * spike_threshold:
            anomalies.append(
                f"high_deny_rate: {deny_rate:.2%} (baseline {baseline_deny_rate:.2%}, "
                f"threshold {spike_threshold}x)"
            )
        if baseline_escalate_rate > 0 and escalate_rate >= baseline_escalate_rate * spike_threshold:
            anomalies.append(
                f"high_escalate_rate: {escalate_rate:.2%} (baseline "
                f"{baseline_escalate_rate:.2%}, threshold {spike_threshold}x)"
            )

        return {
            "total": total,
            "distribution": distribution,
            "rates": distribution,
            "anomalies": anomalies,
            "is_anomalous": len(anomalies) > 0,
            "baseline_deny_rate": baseline_deny_rate,
            "baseline_escalate_rate": baseline_escalate_rate,
        }

    def get_permission_ceiling(self) -> dict[str, Any]:
        return permission_ceiling.get_permission_ceiling(self)

    def rule_regulatory_clause_map(self) -> dict[str, Any]:
        return regulatory.rule_regulatory_clause_map(self)

    @staticmethod
    def check_governance_slo(
        p99_latency_ms: float = 0.0,
        compliance_rate: float = 1.0,
        throughput_rps: float = 0.0,
        false_negative_rate: float = 0.0,
        *,
        max_p99_ms: float = 1.0,
        min_compliance: float = 0.97,
        min_throughput_rps: float = 6000.0,
        max_fn_rate: float = 0.01,
    ) -> dict[str, Any]:
        """exp150: Check observed governance metrics against SLO thresholds (breach detection).

        Compares observed p99, compliance, throughput, and false-negative rate to
        configurable targets. For dashboards and alerting; does not touch the hot path.

        Returns:
            dict with keys:
            - thresholds: {max_p99_ms, min_compliance, min_throughput_rps, max_fn_rate}
            - metrics: {p99_latency_ms, compliance_rate, throughput_rps, false_negative_rate}
            - pass: {p99, compliance, throughput, fn_rate} (bool each)
            - breaches: list of strings describing failed SLOs
            - slo_pass: True if all metrics within SLO
        """
        pass_p99 = p99_latency_ms <= max_p99_ms
        pass_compliance = compliance_rate >= min_compliance
        pass_throughput = throughput_rps >= min_throughput_rps
        pass_fn = false_negative_rate <= max_fn_rate
        breaches: list[str] = []
        if not pass_p99:
            breaches.append(f"p99_latency_ms {p99_latency_ms:.4f} > {max_p99_ms}")
        if not pass_compliance:
            breaches.append(f"compliance_rate {compliance_rate:.4f} < {min_compliance}")
        if not pass_throughput:
            breaches.append(f"throughput_rps {throughput_rps:.0f} < {min_throughput_rps}")
        if not pass_fn:
            breaches.append(f"false_negative_rate {false_negative_rate:.4f} > {max_fn_rate}")
        return {
            "thresholds": {
                "max_p99_ms": max_p99_ms,
                "min_compliance": min_compliance,
                "min_throughput_rps": min_throughput_rps,
                "max_fn_rate": max_fn_rate,
            },
            "metrics": {
                "p99_latency_ms": p99_latency_ms,
                "compliance_rate": compliance_rate,
                "throughput_rps": throughput_rps,
                "false_negative_rate": false_negative_rate,
            },
            "pass": {
                "p99": pass_p99,
                "compliance": pass_compliance,
                "throughput": pass_throughput,
                "fn_rate": pass_fn,
            },
            "breaches": breaches,
            "slo_pass": len(breaches) == 0,
        }

    def list_categories(self) -> list[str]:
        """exp151: Return sorted distinct rule categories for UI/config.

        Does not touch the hot validation path.
        """
        return sorted({r.category for r in self.rules if r.category})

    def blast_radius(self, rule_id: str) -> dict[str, Any]:
        """Change-impact analysis for a single rule. See :mod:`dependency_analysis`."""
        return dependency_analysis.blast_radius(self, rule_id)

    def get_version_info(self) -> dict[str, Any]:
        """exp153: Return version label, hash, and rule count for rollback/documentation.

        Does not touch the hot validation path.
        """
        return {
            "version_name": self.version_name or None,
            "version": self.version,
            "hash": self.hash,
            "rule_count": len(self.rules),
        }

    def maturity_level(self) -> dict[str, Any]:
        """Score governance maturity on a 1-5 capability scale. See :mod:`reporting`."""
        return reporting.maturity_level(self)

    def coverage_gaps(self) -> dict[str, Any]:
        """Identify governance domains with thin or zero coverage. See :mod:`reporting`."""
        return reporting.coverage_gaps(self)

    def health_score(self) -> dict[str, Any]:
        """Composite governance quality metric (0.0-1.0). See :mod:`reporting`."""
        return reporting.health_score(self)

    def dead_rules(
        self,
        corpus: list[str],
        *,
        include_deprecated: bool = False,
    ) -> dict[str, Any]:
        """Detect rules that never fire against a corpus of actions. See :mod:`similarity`."""
        return similarity.dead_rules(self, corpus, include_deprecated=include_deprecated)

    def posture_score(self, ci_threshold: float = 0.70) -> dict[str, Any]:
        """Unified governance posture score for CI/CD gates. See :mod:`reporting`."""
        return reporting.posture_score(self, ci_threshold=ci_threshold)

    def changelog_summary(self) -> dict[str, Any]:
        return workflow_analytics.changelog_summary(self)

    def filter(
        self,
        *,
        severity: str | Severity | None = None,
        min_severity: str | Severity | None = None,
        category: str | None = None,
        workflow_action: str | None = None,
        tag: str | None = None,
        enabled_only: bool = True,
    ) -> Constitution:
        """exp112: Return a new Constitution containing only matching rules.

        Useful for context-aware governance where different environments or agent
        tiers use different rule subsets:

        - Production: only CRITICAL + HIGH rules
        - Staging: all rules including LOW informational
        - Specific domain: only rules in a given category
        - Compliance scope: only rules tagged "gdpr" or "sox"

        Args:
            severity: Keep only rules with this exact severity.
            min_severity: Keep rules at this severity or higher
                (CRITICAL > HIGH > MEDIUM > LOW).
            category: Keep only rules in this category.
            workflow_action: Keep only rules with this workflow_action.
            tag: Keep only rules carrying this tag (exp117).
            enabled_only: If True (default), exclude disabled rules.

        Returns:
            A new Constitution with filtered rules. Preserves name/version/metadata
            with a ``"filtered"`` flag in metadata.

        Raises:
            ValueError: If the filter would produce an empty constitution.

        Example::

            prod_rules = constitution.filter(min_severity="high")
            staging_rules = constitution.filter(category="data-protection")
        """
        return filtering.filter(
            self,
            severity=severity,
            min_severity=min_severity,
            category=category,
            workflow_action=workflow_action,
            tag=tag,
            enabled_only=enabled_only,
        )

    def semantic_rule_clusters(
        self,
        expected_domains: Sequence[str] | None = None,
    ) -> dict[str, list[str]]:
        return coverage_analysis.semantic_rule_clusters(self, expected_domains)

    def analyze_coverage_gaps(
        self,
        expected_domains: Sequence[str] | None = None,
        *,
        weak_threshold: int = 1,
    ) -> dict[str, Any]:
        return coverage_analysis.analyze_coverage_gaps(
            self,
            expected_domains,
            weak_threshold=weak_threshold,
        )

    def render(self, context: dict[str, Any]) -> Constitution:
        return rendering.render(self, context)

    def explain_rendered(self, action: str, context: dict[str, Any]) -> dict[str, Any]:
        return rendering.explain_rendered(self, action, context)

    def builder(self) -> ConstitutionBuilder:
        """Return a ConstitutionBuilder pre-populated with this constitution's rules.

        Useful for creating modified versions of an existing constitution using
        the fluent builder API without mutating the original.

        Example::

            constitution2 = (
                constitution.builder()
                .add_rule("NEW-001", "No new risk", severity="high", keywords=["new risk"])
                .build()
            )
        """
        from .templates import ConstitutionBuilder

        b = ConstitutionBuilder(self.name, version=self.version, description=self.description)
        b._rules = list(self.rules)
        b._rule_ids = {rule.id for rule in self.rules}
        b._metadata = dict(self.metadata)
        return b

    def __len__(self) -> int:
        return len(self.rules)

    def __repr__(self) -> str:
        return f"Constitution(name={self.name!r}, rules={len(self.rules)}, hash={self.hash!r})"
