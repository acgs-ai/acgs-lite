# Contributing a New Compliance Framework

ACGS covers **20 regulatory frameworks**. Adding a 21st is mostly research — the code is a filled-in protocol class (~200 lines).

This guide walks from zero to merged PR.

---

## Before You Start

1. Open a [New Compliance Framework issue](https://github.com/dislovelhl/acgs-lite/issues/new?template=new_compliance_framework.yml)
2. Read the [EU AI Act implementation](https://github.com/dislovelhl/acgs-lite/blob/main/src/acgs_lite/compliance/eu_ai_act.py) as the reference
3. Check `src/acgs_lite/compliance/` — your target framework may already be in progress

---

## The Contribution Ladder

```
Level 1 — Research only:   Document the framework mapping in the issue
Level 2 — Checklist only:  Implement the checklist items (no engine logic)
Level 3 — Full framework:  ComplianceFramework protocol + report + tests
```

Start at Level 1 if you're new. We'll help you get to Level 3.

---

## Step-by-Step

### 1. Research the framework

Answer these questions:

- What are the key articles/sections?
- Which apply to AI systems generally vs. high-risk only?
- Which ACGS features provide automatic coverage?
- Which require user action (can't be auto-checked)?

Create a mapping table (copy to your issue):

| Article | Requirement | ACGS coverage | Status |
|---------|-------------|---------------|--------|
| Art. 9  | Risk management system | `GovernedAgent` + `AuditTrail` | Auto ✅ |
| Art. 10 | Data governance | User-defined rules | Manual ⬜ |
| Art. 11 | Technical documentation | `acgs-lite docs` command | Partial 🟡 |

### 2. Create the framework file

```bash
touch src/acgs_lite/compliance/my_framework.py
```

### 3. Implement the protocol

```python
"""My Regulatory Framework compliance implementation.

Coverage:
  - Article X: [description] → [ACGS feature]
  - ...

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from acgs_lite.compliance.base import (
    ChecklistItem,
    ComplianceFramework,
    ComplianceReport,
    ComplianceStatus,
)

CONSTITUTIONAL_HASH = "608508a9bd224290"


@dataclass
class MyFramework(ComplianceFramework):
    """My Regulatory Framework (MyRF) compliance assessor.

    Covers: [jurisdiction] — [effective date]
    Scope: [who it applies to]
    """

    framework_id: ClassVar[str] = "my_rf"
    framework_name: ClassVar[str] = "My Regulatory Framework"
    jurisdiction: ClassVar[str] = "Country/Region"
    version: ClassVar[str] = "2025"

    def get_checklist(self) -> list[ChecklistItem]:
        return [
            ChecklistItem(
                id="my_rf_art_1",
                article="Article 1",
                requirement="Clear purpose and scope defined",
                acgs_feature="Constitution.from_yaml()",
                status=ComplianceStatus.AUTO,
                evidence_key="constitution_loaded",
                notes="Auto-satisfied when a constitution is loaded.",
            ),
            ChecklistItem(
                id="my_rf_art_2",
                article="Article 2",
                requirement="Human oversight mechanism",
                acgs_feature="MACI EXECUTIVE role",
                status=ComplianceStatus.AUTO,
                evidence_key="maci_executive_assigned",
            ),
            ChecklistItem(
                id="my_rf_art_3",
                article="Article 3",
                requirement="Data minimisation policy",
                acgs_feature="User-defined constitution rules",
                status=ComplianceStatus.MANUAL,
                notes="Add a rule to block PII patterns in your constitution.",
            ),
            # ... add all relevant articles
        ]

    def assess(self, evidence: dict) -> ComplianceReport:
        checklist = self.get_checklist()
        satisfied = []
        gaps = []

        for item in checklist:
            if item.status == ComplianceStatus.AUTO:
                # Check that the ACGS feature providing coverage is active
                if evidence.get(item.evidence_key):
                    satisfied.append(item)
                else:
                    gaps.append(item)
            else:
                # Manual items: check if user has provided evidence
                if evidence.get(item.evidence_key):
                    satisfied.append(item)
                else:
                    gaps.append(item)

        score = len(satisfied) / len(checklist) if checklist else 0.0
        return ComplianceReport(
            framework=self,
            score=score,
            satisfied=satisfied,
            gaps=gaps,
            constitutional_hash=CONSTITUTIONAL_HASH,
        )
```

### 4. Register the framework

```python
# src/acgs_lite/compliance/__init__.py
from acgs_lite.compliance.my_framework import MyFramework

FRAMEWORK_REGISTRY["my_rf"] = MyFramework
```

### 5. Add CLI support (optional)

```python
# src/acgs_lite/cli/commands/compliance_cmd.py
# Add to the FRAMEWORKS dict:
"my-rf": ("my_rf", MyFramework),
```

Then users can run:
```bash
acgs-lite my-rf --system-id "my-system" --domain finance
```

### 6. Write tests

```python
# tests/compliance/test_my_framework.py
import pytest
from acgs_lite.compliance.my_framework import MyFramework

@pytest.fixture
def framework():
    return MyFramework()

def test_checklist_has_items(framework):
    checklist = framework.get_checklist()
    assert len(checklist) > 0

def test_auto_items_satisfied_with_evidence(framework):
    evidence = {
        "constitution_loaded": True,
        "maci_executive_assigned": True,
    }
    report = framework.assess(evidence)
    assert report.score > 0

def test_manual_items_in_gaps_without_evidence(framework):
    report = framework.assess({})
    manual_items = [i for i in report.gaps if i.status.value == "manual"]
    assert len(manual_items) > 0

def test_constitutional_hash_in_report(framework):
    report = framework.assess({})
    assert report.constitutional_hash == "608508a9bd224290"

def test_perfect_score_with_all_evidence(framework):
    checklist = framework.get_checklist()
    evidence = {item.evidence_key: True for item in checklist if item.evidence_key}
    report = framework.assess(evidence)
    assert report.score == pytest.approx(1.0, abs=0.05)
```

### 7. Document it

Add a row to the compliance table in `docs/compliance.md`:

```markdown
| My Regulatory Framework | `MyFramework` | Country/Region | 2025 | N items |
```

---

## Checklist Before Opening a PR

- [ ] Framework file created with `CONSTITUTIONAL_HASH = "608508a9bd224290"`
- [ ] All major articles have a `ChecklistItem`
- [ ] Auto vs. manual status correctly assigned
- [ ] Registered in `FRAMEWORK_REGISTRY`
- [ ] Tests: checklist populated, auto items, manual items, hash present
- [ ] `make test-quick` passes
- [ ] Row added to `docs/compliance.md`
- [ ] Issue linked in PR description

---

## How Coverage Tiers Work

| Tier | Meaning |
|------|---------|
| `AUTO` ✅ | ACGS feature provides coverage automatically |
| `PARTIAL` 🟡 | ACGS provides a foundation; user action also required |
| `MANUAL` ⬜ | Requires user-defined rules or external processes |
| `NA` | Not applicable to most ACGS deployments |
