# Testing Governance: Verifying Fail-Closed Boundaries

**Meta Description**: Learn how to use the ACGS-Lite testing framework to verify that governance rules block prohibited actions and allow legitimate agent actions.

---

A Constitution is code. Like any other code, it must be tested. ACGS-Lite provides a testing framework (`acgs test`) to ensure your governance rules are both **Effective** (blocking prohibited actions) and **Functional** (not blocking legitimate work).

## 🧪 The Testing Workflow

Testing your governance follows a simple 3-step process:
1.  **Define Fixtures**: Create a YAML file with "Safe" and "Dangerous" examples.
2.  **Run Tests**: Use the `acgs test` command.
3.  **Refine Rules**: Adjust your patterns based on False Positives or False Negatives.

---

## 📝 Defining Test Fixtures

Create a file named `governance_tests.yaml`. Each fixture tests a specific expected outcome.

```yaml
# governance_tests.yaml
tests:
  - name: "Block SSN leakage"
    input: "The user's SSN is 123-45-6789"
    expected: "block"
    rule_id: "block-pii"

  - name: "Allow standard medical query"
    input: "What are the common symptoms of a cold?"
    expected: "allow"

  - name: "Block SQL injection attempt"
    input: "SELECT * FROM users; DROP TABLE metadata;"
    expected: "block"
    rule_id: "no-destructive-db"

  - name: "Allow professional greeting"
    input: "Hello team, I have completed the summary."
    expected: "allow"
```

---

## 🚀 Running Your Tests

Run the tests from your terminal:

```bash
acgs test --fixtures governance_tests.yaml --constitution rules.yaml
```

### Understanding the Output

| Result | Meaning | Action |
| :--- | :--- | :--- |
| **PASS** | Expected behavior matched actual behavior. | No action needed. |
| **FAIL (False Positive)** | A "Safe" input was blocked. | Relax your regex pattern or add a `condition`. |
| **FAIL (False Negative)** | A "Dangerous" input was allowed. | Tighten your pattern or add more keywords. |

---

## 🛡️ Advanced Testing Strategies

### 1. Regression Testing
Every time you find a way to bypass your governance (e.g., via a novel prompt injection), add that specific string to your `governance_tests.yaml` to ensure it never happens again.

### 2. Adversarial Fuzzing
Use a second LLM to "attack" your governance engine by generating hundreds of variations of prohibited actions. Feed these into `acgs test` to identify edge cases in your regex patterns.

### 3. Impact Scoring Tests
Verify that your high-stakes rules correctly trigger high impact scores.
```yaml
  - name: "Verify high-risk impact"
    input: "Execute financial transfer of $50,000"
    expected_impact: "CRITICAL"
```

---

## 🚢 CI/CD Integration

Make `acgs test` a mandatory gate in your deployment pipeline. If your governance tests don't pass, the new `rules.yaml` should never reach production.

```bash
# GitHub Action example:
- name: Run Governance Tests
  run: acgs test --fixtures tests.yaml --constitution rules.yaml
```

---

## Next Steps
- Learn more about [Rule Configuration](quickstart.md).
- See the [CLI Reference](cli.md) for more commands.
- Deep dive into [Architecture](architecture.md).
