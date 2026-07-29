# Runbook: Policygen

Goal: generate an adaptive governance policy (constitution) from a pre-context brief,
then submit it through the lifecycle review process before activation.

## Steps

### 0. (Optional) Scan a project for risk-area evidence instead of authoring a brief by hand

`acgs policygen scan <path>` statically scans a project's dependency manifests
(`pyproject.toml`, `requirements.txt`, `package.json`) and maps declared package names to
governance risk areas (e.g. `stripe` -> `financial`, `boto3` -> `production-deploy`). It is a
static, offline, read-only scan: it never imports, introspects, or executes the target
project's code or any discovered package.

**The scan output is evidence only, exactly like a hand-authored brief -- it is never an
activation, grant, or authorization of any kind.** Unknown (unmapped) packages are always
reported explicitly, never silently dropped, and are not treated as errors.

```bash
# Default: print the ManifestScanResult JSON report to stdout (matched risk areas,
# unknown packages, manifests found, and the derived pre-context).
acgs policygen scan ./my-project

# Also write the derived pre-context brief for later `generate --brief` use.
acgs policygen scan ./my-project --brief-out brief.json

# Chain directly into policy generation (equivalent to scan + generate --brief in one step).
acgs policygen scan ./my-project --generate --out policy.constitution.yaml
```

With `--generate`, stdout carries the usual `generate` payload (`summary`, `rationale`,
`output_path`) **plus two extra keys, `matched` and `unknown`, copied from the scan** --
this keeps the scan evidence visible even though `--brief-out`'s `PreContext.to_dict()`
brief has no `unknown` field of its own (unmapped packages are never silently dropped, per
the manifest scanner's evidence-only contract):

```json
{
  "matched": [["boto3", "production-deploy"], ["stripe", "financial"]],
  "output_path": "policy.constitution.yaml",
  "rationale": ["..."],
  "summary": {"...": "..."},
  "unknown": ["some-unrecognized-package"]
}
```

Exit codes: `0` on success, even when unknown packages are reported (they are evidence, not
errors). `1` when the path is not a directory or no supported manifest file is found there.

Continue to step 3 below (review and approve through lifecycle) for any YAML produced this
way -- a scan-generated constitution is exactly as much a **DRAFT artifact** as one produced
from a hand-authored brief, and it is bound by the same no-auto-activation rule.

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

The example shows common fields. The `domain` field is required. All other fields are
optional and fall back to defaults if omitted. Unknown keys are rejected. See
`PreContext.to_dict()` for the full key set. Save as `brief.json`.

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
| `scan root is not a directory` | `<path>` doesn't exist or isn't a dir | Verify the path |
| `no supported manifest files ... found` | No manifest at root | Point `scan` at the project root |
| `Malformed pyproject.toml` / `package.json` | Not valid TOML/JSON | Fix the manifest syntax |
