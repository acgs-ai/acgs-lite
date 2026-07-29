# Runbook: Policygen

Goal: generate an adaptive governance policy (constitution) from a pre-context brief,
then submit it through the lifecycle review process before activation.

## Steps

### 1. Author a pre-context brief

Create a JSON file documenting the governance domain. Use `PreContext.to_dict()` format
from `src/acgs_lite/policygen/context.py`:

```json
{
  "domain": "content-moderation",
  "description": "Real-time moderation of user-generated content...",
  "environment": "production",
  "frameworks": ["GDPR", "DSA"],
  "risk_areas": ["data-retention", "transparency"],
  "risk_level": "high",
  "custom_requirements": "..."
}
```

All fields except `custom_requirements` are required. Save as `brief.json`.

### 2. Generate the policy

Set environment variables for the LLM providers:

```bash
export OPENAI_API_KEY=<your-key>
export ANTHROPIC_API_KEY=<your-key>
```

Run the generator:

```bash
acgs policygen generate --brief brief.json --out policy.constitution.yaml
```

The command outputs a JSON summary to stdout and writes the DRAFT constitution to
`policy.constitution.yaml`.

### 3. Review and approve through lifecycle

**IMPORTANT:** The generated `policy.constitution.yaml` is a **DRAFT artifact** only.
It cannot be activated until submitted for human review and approval through the
lifecycle API. This is the MACI (Monitoring, Accounting, Consistency, Integrity)
separation requirement — policy decisions require explicit governance approval.

To submit for review:

```bash
acgs constitution lifecycle submit --constitution policy.constitution.yaml \
  --reviewer human-reviewer@org.io
```

The lifecycle system enforces state transitions (DRAFT → IN_REVIEW → APPROVED), and only
approved constitutions may be activated.

## Verify

Check that:
1. The generated YAML is syntactically valid:
   ```bash
   python3 -c "import yaml; yaml.safe_load(open('policy.constitution.yaml'))"
   ```
2. The lifecycle submission was recorded:
   ```bash
   acgs constitution lifecycle status --constitution policy.constitution.yaml
   ```
3. The policy output contains required sections (rules, rationale, metadata).

## Failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `invalid JSON in brief file` | Malformed JSON | Run `jq . brief.json` |
| `brief file is not JSON object` | Valid JSON but not object | Wrap in `{}` |
| `malformed pre-context` | Missing/invalid field | Check PreContext schema |
| `failed to generate policy` | LLM error or rate limit | Verify API keys |
| `could not write output` | Permission or path error | Verify directory writable |
| Lifecycle submission rejected | Policy violates constraint | Review lifecycle feedback |
