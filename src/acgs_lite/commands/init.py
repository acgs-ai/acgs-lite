# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs init — scaffold rules.yaml + CI governance job."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_DEFAULT_RULES_YAML = """\
# ACGS Constitutional Rules
# See: https://acgs.ai | pip install acgs
# EU AI Act main high-risk obligations: December 2, 2027
# (Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus)

rules:
  - id: safety-001
    text: "Reject actions that could cause physical harm to humans"
    severity: critical
    keywords: ["harm", "injure", "kill", "weapon", "attack"]
    category: safety

  - id: privacy-001
    text: "Block unauthorized access to personal data"
    severity: high
    keywords: ["personal data", "PII", "SSN", "social security"]
    patterns: ["\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"]
    category: privacy

  - id: bias-001
    text: "Flag decisions that discriminate based on protected characteristics"
    severity: high
    keywords: ["race", "gender", "religion", "disability", "age"]
    category: fairness

  - id: transparency-001
    text: "Require explanation for consequential automated decisions"
    severity: medium
    keywords: ["reject", "deny", "terminate", "suspend"]
    category: transparency

  - id: oversight-001
    text: "Escalate high-impact decisions for human review"
    severity: medium
    keywords: ["approve", "authorize", "deploy", "release"]
    category: oversight
"""

_GITLAB_CI_SNIPPET = """\
# ACGS Governance Gate
# Verifies rules.yaml loads and reports the constitutional hash
# Docs: https://acgs.ai
# EU AI Act main high-risk obligations: December 2, 2027
# (Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus)

governance:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install acgs
  script:
    - python3 -c "
      from acgs import Constitution, GovernanceEngine;
      c = Constitution.from_yaml('rules.yaml');
      e = GovernanceEngine(c);
      print(f'Constitutional hash: {c.hash}');
      print(f'Rules loaded: {len(c.rules)}');
      print('Constitution loaded — hash pinned');
      "
  rules:
    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
"""

_GITHUB_ACTIONS_SNIPPET = """\
# ACGS Governance Gate
# Verifies rules.yaml loads and reports the constitutional hash
# Docs: https://acgs.ai
# EU AI Act main high-risk obligations: December 2, 2027
# (Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus)

name: ACGS Governance
on:
  pull_request:
    branches: [main]

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install acgs
      - run: |
          python3 -c "
          from acgs import Constitution, GovernanceEngine
          c = Constitution.from_yaml('rules.yaml')
          e = GovernanceEngine(c)
          print(f'Constitutional hash: {c.hash}')
          print(f'Rules loaded: {len(c.rules)}')
          print('Constitution loaded — hash pinned')
          "
"""


def add_parser(sub: argparse._SubParsersAction) -> None:
    """Register the init subcommand."""
    p = sub.add_parser("init", help="Scaffold rules.yaml + CI governance job")
    p.add_argument("--force", action="store_true", help="Overwrite existing files")


def handler(args: argparse.Namespace) -> int:
    """Scaffold rules.yaml and CI governance job in the current directory."""
    rules_path = Path("rules.yaml")
    force: bool = getattr(args, "force", False)

    if rules_path.exists() and not force:
        print("  rules.yaml already exists. Use --force to overwrite.", file=sys.stderr)
        return 1

    rules_path.write_text(_DEFAULT_RULES_YAML, encoding="utf-8")
    print(f"  ✅ Created rules.yaml ({5} rules)")

    # Generate acgs.json config
    config_path = Path("acgs.json")
    if not config_path.exists() or force:
        config = {
            "system_id": Path.cwd().name,
            "jurisdiction": "european_union",
            "domain": "",
            "rules": "rules.yaml",
            "_comment": (
                "Edit jurisdiction/domain for auto-framework selection. See: acgs assess --help"
            ),
        }
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        print("  ✅ Created acgs.json (edit jurisdiction + domain)")
    else:
        print("  ℹ️  acgs.json already exists")

    # Detect CI system
    ci_path: Path | None = None
    ci_name = ""

    if Path(".gitlab-ci.yml").exists():
        ci_path = Path(".gitlab-ci.yml")
        ci_name = "GitLab CI"
        snippet = _GITLAB_CI_SNIPPET
    elif Path(".github/workflows").is_dir():
        ci_path = Path(".github/workflows/acgs-governance.yml")
        ci_name = "GitHub Actions"
        snippet = _GITHUB_ACTIONS_SNIPPET
    else:
        ci_path = Path(".gitlab-ci.yml")
        ci_name = "GitLab CI (new)"
        snippet = _GITLAB_CI_SNIPPET

    if ci_path and ci_path.exists() and not force:
        print(f"  ℹ️  {ci_path} exists — add this to your pipeline:")
        print()
        print(snippet)
    elif ci_path:
        ci_path.parent.mkdir(parents=True, exist_ok=True)
        if ci_path.exists():
            with ci_path.open("a", encoding="utf-8") as f:
                f.write("\n\n" + snippet)
            print(f"  ✅ Appended governance job to {ci_path}")
        else:
            ci_path.write_text(snippet, encoding="utf-8")
            print(f"  ✅ Created {ci_path} ({ci_name})")

    print()
    print("  Next steps:")
    print("    1. Edit rules.yaml to match your governance requirements")
    print("    2. Run: acgs assess")
    print("    3. Run: acgs report --pdf")
    print()
    print(
        "  EU AI Act main high-risk deadline: December 2, 2027 "
        "(Annex III stand-alone high-risk; deferred by the 2026 Digital Omnibus)"
    )
    print("  Docs: https://acgs.ai")

    return 0
