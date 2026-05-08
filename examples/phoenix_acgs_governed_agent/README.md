# Phoenix + ACGS-lite Governed Execution Reference

End-to-end reference implementation of `request -> decision -> receipt -> bounded execution`
with [Arize Phoenix](https://github.com/Arize-ai/phoenix) telemetry. Each
``GovernedCallable``-wrapped tool call produces one ``acgs.governed_execution``
span carrying the decision outcome, receipt id/hash, and constitution version.
The ``governance.decision.*`` attributes are experimental.

Read the schema first — `GOVERNANCE_ATTRIBUTES.md` documents the exact
attributes emitted on each span. Then `ARCHITECTURE.md` explains the
context-manager pattern and span lifecycle. `UPSTREAM_STRATEGY.md`
covers the plan for promoting this into the upstream Phoenix docs.

## Prerequisites

- Python 3.10+
- `acgs-lite` (this example uses a local editable install during
  development — see Quick Start below)

## Quick Start (mock LLM, console export)

No API key, no Phoenix UI — just verify the spans look right:

```bash
# From this directory
pip install -e ../../              # acgs-lite editable install
pip install opentelemetry-sdk pytest
python run.py --mock --scenario all
```

You should see four spans, one per scenario, printed to stdout as JSON,
each with a `governance.decision.outcome` attribute.

## With Phoenix UI (in-process)

Launch Phoenix in the same Python process and watch spans land in real
time:

```bash
pip install -e ../../
pip install arize-phoenix opentelemetry-sdk
python run.py --mock --scenario all --phoenix-mode in-process
```

This calls `phoenix.otel.register()` which spins up a local Phoenix
server on `localhost:6006` and registers an OTLP exporter. Open
`http://localhost:6006` in a browser to filter by
`governance.decision.outcome`.

## With a real OpenAI key (in-process Phoenix)

Adds an LLM child span under each governed-execution parent span — this
is what you'd see in production:

```bash
cp .env.example .env
# edit .env, set OPENAI_API_KEY=sk-...
export $(grep -v '^#' .env | xargs)
python run.py --scenario all --phoenix-mode in-process
```

## Phoenix External-Daemon Path

If you'd rather run Phoenix as a separate long-running daemon (recommended
for shared dev / on-call dashboards):

```bash
# In one terminal, start Phoenix as a service
phoenix serve

# In another terminal, point this example at it
PHOENIX_HOST=localhost PHOENIX_PORT=6006 \
  python run.py --mock --scenario all --phoenix-mode in-process
```

The `--phoenix-mode in-process` switch will detect a running daemon and
register against it instead of launching a new one.

## Scenarios

| Scenario | Trigger input | Expected outcome | Span status |
| --- | --- | --- | --- |
| `allow` | "What is the weather in Paris?" | `allow` | OK |
| `deny` | "My SSN is 123-45-6789..." | `deny` | ERROR |
| `review` | "Please initiate payment / wire transfer..." | `review` | OK (pending) |
| `fail-closed` | (tool body raises `RuntimeError`) | `fail-closed` | ERROR |

Each scenario produces exactly one ``acgs.governed_execution`` span
plus, when an LLM is exercised, child spans from the OpenInference
OpenAI instrumentor.

## Expected Trace Shape

Per scenario, you'll see this in Phoenix:

```
acgs.governed_execution                         <- parent (this example)
  ├── attributes.governance.decision.outcome = allow|deny|review|fail-closed
  ├── attributes.governance.decision.reason
  ├── attributes.governance.decision.rule_id
  ├── attributes.acgs.receipt.id
  ├── attributes.acgs.receipt.hash
  └── (optional child) openai.chat.completions  <- from OpenInference, when --mock is off
```

## Tests

```bash
python -m pytest test_phoenix_integration.py -v --import-mode=importlib
```

Six tests, ~37 assertions, all using ``InMemorySpanExporter`` so the
suite needs neither network nor Phoenix.

## Files

| File | Purpose |
| --- | --- |
| `constitution.yaml` | Three rules (deny / review / allow) |
| `governance_span.py` | Context manager that creates the parent span |
| `mock_llm.py` | Deterministic stub LLM — no API key required |
| `run.py` | CLI driver for all four scenarios |
| `test_phoenix_integration.py` | Span-level assertions per scenario |
| `GOVERNANCE_ATTRIBUTES.md` | Finalized OTel attribute schema |
| `ARCHITECTURE.md` | Data flow + span lifecycle |
| `UPSTREAM_STRATEGY.md` | Plan for the Phoenix docs PR |
| `requirements.txt` | Dependencies |
| `.env.example` | Sample env vars |
