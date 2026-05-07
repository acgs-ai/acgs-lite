# Governance Span Attribute Schema

This document is the **finalized schema** for OpenTelemetry span attributes
emitted by the Phoenix + ACGS-lite governed-execution example. The schema
must be agreed before any test assertions are written so test code can
target stable attribute names.

## Span Levels

The example produces (and the runtime library already emits) two distinct
span types. Each span type has a different scope and a different audience.

### 1. `acgs.governance.request` spans (HTTP-request level)

- **Source**: emitted by the library's `GovernanceMetricsMiddleware` (ASGI
  middleware) on every HTTP request to a governed FastAPI surface.
- **Scope**: covers a full request/response cycle.
- **Use case**: ops dashboards, SLOs, request-level trends.
- **Existing attributes (do NOT redefine on `acgs.governed_execution`):**
  - `acgs.constitutional_hash` — string, hash of the active constitution
  - `acgs.rules_count` — int, number of rules evaluated
  - `acgs.compliance_score` — float, fraction of rules passed
  - `acgs.audit_chain_valid` — boolean, audit chain integrity check

### 2. `acgs.governed_execution` spans (per-tool-call level)

- **Source**: emitted by `governance_span()` context manager in this
  example (`governance_span.py`).
- **Scope**: covers one wrapped tool call (one decision, one audit entry).
- **Use case**: receipt correlation, decision breakdown, deny/review triage.
- **Carries**: the `governance.*` (generic) and `acgs.*` (vendor) attributes
  defined below.

The two span types nest naturally — a single HTTP request may span multiple
governed tool calls. Phoenix renders both because both ride OTLP.

## Attributes on `acgs.governed_execution` Spans

Two namespaces are used so a future upstream contribution can land
the **generic** half without coupling Phoenix to the vendor half.

### Generic (`governance.*` namespace, upstream-ready)

| Attribute | Type | Description |
| --- | --- | --- |
| `governance.decision.outcome` | string | Enum: `allow`, `deny`, `review`, `fail-closed` |
| `governance.decision.reason` | string | Human-readable reason (e.g. policy name, exception text) |
| `governance.decision.rule_id` | string | Identifier of the rule that triggered the decision (empty for `allow`) |
| `governance.decision.version` | string | Constitution / policy version string |

### Vendor-specific (`acgs.*` namespace)

| Attribute | Type | Description |
| --- | --- | --- |
| `acgs.receipt.id` | string | Audit-entry id (`AuditEntry.id`) — the unique receipt for this decision |
| `acgs.receipt.hash` | string | Audit-entry hash (`AuditEntry.entry_hash`) — short SHA prefix |
| `acgs.policy.version` | string | Constitution version, mirrored for vendor-side dashboards |
| `acgs.fail_closed` | boolean | Whether `GovernedCallable.strict=True` was in effect for this call |
| `acgs.review.auto_approved` | boolean | (review only) Whether an auto-approval policy fired |
| `acgs.review.outcome` | string | (review only) `pending` while waiting; `approved` / `rejected` after a human acts |

## Outcome → Attribute Cheat Sheet

| Outcome | Span status | Generic attrs | Vendor attrs |
| --- | --- | --- | --- |
| `allow` | OK | `governance.decision.outcome=allow`, `reason="policy evaluation passed"` | `acgs.receipt.id`, `acgs.receipt.hash` |
| `deny` | ERROR | `governance.decision.outcome=deny`, `reason=<exception text>`, `rule_id` | `acgs.receipt.id`, `acgs.receipt.hash` |
| `review` | OK | `governance.decision.outcome=review`, `reason="requires human review"`, `rule_id` | `acgs.review.auto_approved=false`, `acgs.review.outcome=pending` |
| `fail-closed` | ERROR | `governance.decision.outcome=fail-closed`, `reason=<exception text>` | `acgs.receipt.*` (best-effort) |

## Why this schema (rationale)

- **Two namespaces** — Phoenix (and any other OTLP backend) only needs the
  generic `governance.*` attributes to render outcome dashboards. The
  `acgs.*` half stays vendor-specific so the upstream Phoenix docs PR
  can land without committing Phoenix to ACGS semantics.
- **Outcome is an enum, not a boolean** — `deny` and `review` are
  meaningfully different. A boolean would lose the queue-for-review case.
- **`fail-closed` is a first-class outcome** — distinguishing
  policy-driven denies from infrastructure failures is essential for
  on-call triage and for fail-closed verification.
- **Receipt id + hash live alongside outcome** — letting auditors pivot
  from a Phoenix span straight to the matching audit-log entry without
  a separate query.
- **No reuse of middleware attributes** — the four middleware-level
  attributes (`acgs.constitutional_hash`, `acgs.rules_count`, ...) are
  HTTP-request scope; redefining them per tool call would dilute their
  meaning and break existing ops dashboards.
