# CLI Reference: Mastering the ACGS Command Line

**Meta Description**: Explore the ACGS-Lite CLI. Learn how to scaffold projects, run compliance assessments, generate reports, and manage policy lifecycles from your terminal.

---

The ACGS-Lite CLI is the primary interface for managing your governance infrastructure in CI/CD pipelines and local development. The CLI is available as both `acgs` (preferred) and `acgs-lite` (compatibility alias).

## 🛠️ Core Commands

### `acgs init`
Scaffold a new governance project. Creates a default `rules.yaml` and a `.github/workflows/governance.yml` template.
```bash
acgs init --name "my-secure-agent"
```

### `acgs assess`
Run a multi-framework compliance assessment against your active constitution.
```bash
# Assess against EU AI Act and NIST AI RMF
acgs assess --jurisdiction european_union --framework nist_rmf
```

### `acgs report`
Generate an auditor-ready compliance report based on your latest assessment.
```bash
# Generate a detailed PDF report
acgs report --pdf --output report.pdf
```

### `acgs lint`
Check your `rules.yaml` for common errors, redundant patterns, or stale constitutional hashes.
```bash
acgs lint rules.yaml
```

### `acgs test`
Run your governance test fixtures to verify that your rules correctly block prohibited patterns and allow safe ones.
```bash
acgs test --fixtures tests/governance_fixtures.yaml
```

### `acgs lean-smoke`
Validate the configured Lean runtime by running a minimal theorem through the same kernel path used by Lean proof verification.
```bash
# Preferred exact command form
export ACGS_LEAN_CMD='["lake", "env", "lean"]'
export ACGS_LEAN_WORKDIR=/absolute/path/to/lean-project
acgs lean-smoke --json

# Or use a wrapper script when you need shell setup
export ACGS_LEAN_CMD="$(pwd)/examples/lean_runtime/lean-wrapper.sh"
acgs lean-smoke
```

If you want a real-toolchain pytest integration in CI, set:
```bash
export LEAN_INTEGRATION=1
```
The integration test auto-runs only when that variable is set to `1`.

---

## 📈 Observability & Telemetry

### `acgs observe`
Export real-time governance telemetry. Useful for local debugging of governed execution decisions.
```bash
acgs observe "Analyze the financial report" --prometheus
```

### `acgs otel`
Export OpenTelemetry-compatible telemetry to your centralized collector (e.g., Jaeger, Honeycomb, or Datadog).
```bash
acgs otel --endpoint http://localhost:4317
```

---

## ⚖️ Policy Lifecycle Management

### `acgs lifecycle`
Manage the promotion of rules from `experimental` to `production` based on their performance in shadow mode.
```bash
acgs lifecycle promote --rule-id "no-pii"
```

### `acgs refusal`
Explain the most recent governance denial. Use this to help your agent understand *why* it was blocked and suggest safer alternatives.
```bash
acgs refusal --last
```

---

## 🔑 Licensing & Status

### `acgs status`
Show your current license tier (Community, Pro, or Enterprise) and enabled features.
```bash
acgs status
```

### `acgs activate`
Activate your Pro or Enterprise license key.
```bash
acgs activate ACGS-PRO-XXXX-XXXX
```

### `acgs verify`
Validate local license key integrity only. It does not validate constitutional hash
integrity; use `acgs lint rules.yaml` to catch stale or mismatched rule hashes.
```bash
acgs verify
```

---

## 🚀 Pro Tip: CI/CD Integration

Integrate ACGS-Lite into your GitLab or GitHub pipelines to gate pipeline runs so unverified code or policy changes fail CI before merge (enforce with branch protection).

```bash
# In your CI script:
acgs lint rules.yaml && acgs test --fixtures tests.yaml
```

!!! info "Constitutional Hash"
    `608508a9bd224290` is the canonical hash for this release. If `acgs lint` reports a mismatch, your rules may have been modified or are out of date.
