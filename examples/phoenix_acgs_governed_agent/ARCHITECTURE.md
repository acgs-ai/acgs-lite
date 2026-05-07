# Architecture

How the Phoenix + ACGS-lite governed-execution telemetry example fits
together. Companion to `GOVERNANCE_ATTRIBUTES.md` (the schema) and
`UPSTREAM_STRATEGY.md` (the contribution plan).

## Data Flow

```
Input
  ↓
GovernedCallable(constitution)(my_tool_fn)   ← two-step decorator factory
  ↓                                            (instance, then decorate)
governance_span() context manager
  → tracer.start_as_current_span("acgs.governed_execution")
  → wrapped_fn(input)                        ← per-call validation + execution
  → catches ConstitutionalViolationError
  → looks up rule.workflow_action for deny vs review classification
  → sets governance.decision.outcome, acgs.receipt.* attributes
  ↓
OpenInference instrumentor (auto-traces any LLM calls as child spans)
  ↓
OTLP exporter → Phoenix ingestion → governed-execution observability
```

## Span Lifecycle

For each scenario, the lifecycle of a single
``acgs.governed_execution`` span:

### allow

1. Enter context manager → start span, set baseline attributes.
2. ``wrapped_fn(input)`` succeeds → record attribute
   ``governance.decision.outcome="allow"``.
3. Pull most recent audit-log entry id + hash → record
   ``acgs.receipt.id`` / ``acgs.receipt.hash``.
4. ``span.set_status(OK)``.
5. Yield ``(span, result, None)`` to caller. Span ends on context exit.

### deny

1. Enter context manager → start span, set baseline attributes.
2. ``wrapped_fn(input)`` raises ``ConstitutionalViolationError``.
3. Look up rule by ``rule_id`` → ``rule.workflow_action == BLOCK``.
4. Record ``governance.decision.outcome="deny"``, rule id, exception text.
5. ``span.set_status(ERROR, message=str(e))``.
6. Yield ``(span, None, e)``. The exception is **not** re-raised by the
   context manager — the caller chooses how to surface deny.

### review

1. Enter context manager → start span, set baseline attributes.
2. ``wrapped_fn(input)`` raises ``ConstitutionalViolationError``.
3. Look up rule by ``rule_id`` →
   ``rule.workflow_action == REQUIRE_HUMAN_REVIEW``.
4. Record ``governance.decision.outcome="review"`` plus
   ``acgs.review.outcome="pending"`` and
   ``acgs.review.auto_approved=false``.
5. ``span.set_status(OK)`` — pending review is not an error condition.
6. Yield ``(span, None, e)``. Operator may approve or reject later.

### fail-closed

1. Enter context manager → start span, set baseline attributes.
2. ``wrapped_fn(input)`` raises an unexpected exception type
   (``RuntimeError``, ``ValueError``, ...).
3. Record ``governance.decision.outcome="fail-closed"`` and reason.
4. ``span.set_status(ERROR, message=str(e))``.
5. Yield ``(span, None, e)`` first so caller can observe.
6. Re-raise the exception so the surrounding system fails closed.

## Why Not a SpanProcessor?

A natural alternative would be a custom ``SpanProcessor`` that mutates
spans on completion (`on_end`) to add ``governance.*`` attributes
post-hoc. We deliberately reject that approach:

- **Phoenix filters at ingestion time.** Phoenix builds its filterable
  attribute index from the data delivered with the span. Attributes
  added post-hoc by an exporter or downstream processor are not
  guaranteed to flow through the OTLP exporter alongside the span body.
- **Span attributes set after `end()` are spec-undefined.** OpenTelemetry
  forbids attribute mutation after span end; some SDKs silently drop the
  write, others keep it. Either way, downstream backends cannot rely on
  it.
- **The decision must precede the export.** ACGS-Lite knows the outcome
  before the tool call returns; setting the attribute *during* the span
  matches reality and avoids tooling fragility.

The context-manager pattern keeps attribute-setting on the same code
path that performs the validation, so what Phoenix sees and what the
audit log sees are guaranteed to agree.

## Span Levels

Two distinct OTel span types are produced. They co-exist; neither
duplicates the other.

| Level | Span name | Source | Scope | Carries |
| --- | --- | --- | --- | --- |
| HTTP-request | `acgs.governance.request` | `GovernanceMetricsMiddleware` (ASGI middleware in acgs-lite) | One request to a governed FastAPI surface | `acgs.constitutional_hash`, `acgs.rules_count`, `acgs.compliance_score`, `acgs.audit_chain_valid` |
| Tool-call | `acgs.governed_execution` | `governance_span()` context manager (this example) | One ``GovernedCallable``-wrapped tool invocation | `governance.decision.*`, `acgs.receipt.*`, `acgs.review.*` |

A single HTTP request span typically parents zero, one, or many
governed-execution spans. Phoenix renders both naturally because both
ride OTLP.

## Module Map

```
examples/phoenix_acgs_governed_agent/
├── constitution.yaml             # 3 rules: deny PII, review payments, allow general
├── governance_span.py            # Context manager that wraps a per-call invocation
├── mock_llm.py                   # Deterministic stub, no API key required
├── run.py                        # CLI runner: --scenario {allow,deny,review,fail-closed,all}
├── test_phoenix_integration.py   # InMemorySpanExporter assertions per scenario
├── GOVERNANCE_ATTRIBUTES.md      # Finalized attribute schema (read first)
├── ARCHITECTURE.md               # This file
├── UPSTREAM_STRATEGY.md          # Plan for upstreaming to arize-phoenix docs
├── README.md                     # Quick start
├── requirements.txt              # acgs-lite + Phoenix + OTel + pytest
└── .env.example                  # OPENAI_API_KEY, PHOENIX_HOST, PHOENIX_PORT
```
