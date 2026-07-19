"""
ACGS-Lite Compliance Report Generator
======================================
Generates organized, human-readable compliance assessment reports for three
representative AI system profiles across all 19 supported regulatory frameworks.

No API keys required — all assessments run fully offline.

Run:
    python examples/compliance_reports/run.py

Output directory:
    examples/compliance_reports/reports/
    ├── INDEX.md                      — master summary table, all profiles
    ├── EXPLAINED.md                  — what every field and file type means
    ├── all_frameworks/               — all 19 frameworks, general AI system
    │   ├── summary.txt
    │   ├── summary.md
    │   ├── summary.json
    │   └── by_framework/
    │       ├── <framework_id>.md     — per-framework Markdown detail
    │       └── <framework_id>.json   — per-framework machine-readable data
    ├── healthcare/                   — HIPAA + GDPR + NIST + ISO profile
    │   ├── summary.txt / .md / .json
    ├── financial/                    — DORA + SOC2 + Fair Lending profile
    │   ├── summary.txt / .md / .json
    └── hr_recruitment/               — EU AI Act (high-risk) + NYC LL144 profile
        ├── summary.txt / .md / .json

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from acgs_lite.compliance import (
    ComplianceReportExporter,
    MultiFrameworkAssessor,
)
from acgs_lite.compliance.base import MultiFrameworkReport
from acgs_lite.compliance.multi_framework import _FRAMEWORK_REGISTRY  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Output root
# ---------------------------------------------------------------------------

REPORTS_DIR = Path(__file__).parent / "reports"

# ---------------------------------------------------------------------------
# System profiles
# ---------------------------------------------------------------------------

ALL_FRAMEWORK_IDS = sorted(_FRAMEWORK_REGISTRY.keys())

PROFILES: list[dict] = [
    {
        "profile_id": "all_frameworks",
        "label": "General AI System — All 19 Frameworks",
        "description": (
            "A general-purpose AI assistant with audit logging and human oversight enabled. "
            "Assessed against every framework in the registry to show the broadest possible "
            "compliance surface."
        ),
        "system": {
            "system_id": "general-ai-assistant-v1",
            "domain": "general_purpose_ai",
            "jurisdiction": "international",
            "has_human_oversight": True,
            "has_audit_log": True,
            "has_risk_management": False,
            "has_data_governance": False,
            "has_explainability": False,
            "processes_personal_data": True,
        },
        "frameworks": ALL_FRAMEWORK_IDS,
    },
    {
        "profile_id": "healthcare",
        "label": "Healthcare AI — Clinical Decision Support",
        "description": (
            "A clinical decision-support AI processing patient data. "
            "HIPAA, GDPR, NIST AI RMF, ISO 42001, and OECD AI Principles apply."
        ),
        "system": {
            "system_id": "clinical-decision-ai-v1",
            "domain": "healthcare",
            "jurisdiction": "european_union",
            "has_human_oversight": True,
            "has_audit_log": True,
            "has_risk_management": True,
            "has_data_governance": False,
            "processes_personal_data": True,
        },
        "frameworks": None,  # auto-select from jurisdiction + domain
    },
    {
        "profile_id": "financial",
        "label": "Financial AI — Fraud Detection",
        "description": (
            "A fraud-detection AI for a regulated financial institution. "
            "DORA, SOC 2, NIST AI RMF, US Fair Lending, and OECD AI Principles apply."
        ),
        "system": {
            "system_id": "fraud-detection-ai-v1",
            "domain": "financial",
            "jurisdiction": "united_states",
            "has_human_oversight": True,
            "has_audit_log": True,
            "has_risk_management": True,
            "has_data_governance": True,
            "processes_personal_data": True,
        },
        "frameworks": None,
    },
    {
        "profile_id": "hr_recruitment",
        "label": "HR Recruitment AI — CV Screener (EU High-Risk)",
        "description": (
            "A CV-screening AI deployed in the EU. Automatically classified as "
            "EU AI Act high-risk. NYC LL144, GDPR, and ISO 42001 also apply."
        ),
        "system": {
            "system_id": "cv-screener-v1",
            "domain": "hr_recruitment",
            "jurisdiction": "european_union",
            "has_human_oversight": True,
            "has_audit_log": True,
            "has_risk_management": False,
            "has_data_governance": False,
            "processes_personal_data": True,
        },
        "frameworks": None,
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCORE_LABEL = [
    (0.90, "Excellent"),
    (0.75, "Good"),
    (0.50, "Fair"),
    (0.25, "Needs Improvement"),
    (0.00, "Critical Gaps"),
]


def _score_label(score: float) -> str:
    for threshold, label in _SCORE_LABEL:
        if score >= threshold:
            return label
    return "Unknown"


def _score_bar(score: float, width: int = 20) -> str:
    filled = round(score * width)
    return "█" * filled + "░" * (width - filled)


def _pct(score: float) -> str:
    return f"{score:.1%}"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Per-framework individual files
# ---------------------------------------------------------------------------


def _write_framework_files(
    report: MultiFrameworkReport,
    out_dir: Path,
) -> list[dict]:
    """Write one .md and one .json file per framework. Returns index rows."""
    fw_dir = out_dir / "by_framework"
    rows = []

    for fid in sorted(report.frameworks_assessed):
        fa = report.by_framework.get(fid)
        if fa is None:
            continue

        # Markdown: framework detail section + header
        md_lines = [
            f"# {fa.framework_name}",
            "",
            f"**Framework ID:** `{fa.framework_id}`  ",
            f"**Score:** {_pct(fa.compliance_score)} — {_score_label(fa.compliance_score)}  ",
            f"**ACGS-lite auto-coverage:** {_pct(fa.acgs_lite_coverage)}  ",
            f"**Assessed:** {fa.assessed_at[:19]}  ",
            f"**Open gaps:** {len(fa.gaps)}  ",
            "",
            "> *Indicative self-assessment only. Not legal advice.*",
            "",
        ]
        md_lines += ComplianceReportExporter.framework_summary_markdown(fa).splitlines()
        _write(fw_dir / f"{fid}.md", "\n".join(md_lines))

        # JSON: full framework assessment
        _write(fw_dir / f"{fid}.json", json.dumps(fa.to_dict(), indent=2, default=str))

        rows.append(
            {
                "id": fid,
                "name": fa.framework_name,
                "score": fa.compliance_score,
                "coverage": fa.acgs_lite_coverage,
                "gaps": len(fa.gaps),
                "label": _score_label(fa.compliance_score),
            }
        )

    return rows


# ---------------------------------------------------------------------------
# Master INDEX.md
# ---------------------------------------------------------------------------

FRAMEWORK_DESCRIPTIONS: dict[str, str] = {
    "nist_ai_rmf": "US AI Risk Management Framework (GOVERN/MAP/MEASURE/MANAGE functions)",
    "iso_42001": "ISO 42001 — International AI Management System standard",
    "gdpr": "EU General Data Protection Regulation — automated decisions & profiling",
    "eu_ai_act": "EU AI Act (Regulation 2024/1689) — tiered-risk classification",
    "dora": "EU Digital Operational Resilience Act — financial-sector ICT/AI resilience",
    "soc2_ai": "SOC 2 Trust Service Criteria with AI-specific controls",
    "hipaa_ai": "HIPAA — Healthcare AI & protected health information (PHI) rules",
    "us_fair_lending": "ECOA + FCRA + US fair lending laws for credit AI models",
    "nyc_ll144": "NYC Local Law 144 — Automated Employment Decision Tools",
    "oecd_ai": "OECD AI Principles (46 countries) — transparency, accountability, safety",
    "canada_aida": "Canada AIDA — Artificial Intelligence and Data Act (Bill C-27)",
    "singapore_maigf": "Singapore PDPC Model AI Governance Framework v2",
    "uk_ai_framework": "UK Cross-Sector AI Principles (AI White Paper, 2023)",
    "india_dpdp": "India Digital Personal Data Protection Act 2023",
    "australia_ai_ethics": "Australia 8-Principle AI Ethics Framework",
    "brazil_lgpd": "Brazil LGPD + Article 20 Automated Decision-Making",
    "china_ai": "China Algorithmic Recommendations + Deep Synthesis + GenAI + PIPL",
    "ccpa_cpra": "California CCPA/CPRA + Automated Decision-Making Technology rules",
    "igaming": "iGaming / Online Gambling AI — Malta, Gibraltar, UK sector rules",
}


def _build_index(
    all_profile_results: list[dict],
    generated_at: str,
) -> str:
    lines = [
        "# ACGS-Lite Compliance Reports — Index",
        "",
        f"Generated: {generated_at}",
        "",
        "This directory contains compliance assessment reports for AI systems assessed "
        "against up to 19 regulatory frameworks using acgs-lite's built-in compliance engine.",
        "",
        "No API keys required. All assessments run offline.",
        "",
        "---",
        "",
        "## How to Read These Reports",
        "",
        "| Term | Meaning |",
        "|------|---------|",
        "| **Score** | Fraction of checklist items marked compliant (0–100%) |",
        "| **ACGS coverage** | Fraction of requirements for which acgs-lite provides "
        "supporting technical measures |",
        "| **Gaps** | Items not yet compliant — each has an actionable recommendation |",
        "| **Cross-framework gaps** | Requirements that appear in multiple frameworks simultaneously |",
        "| **Excellent / Good / Fair** | Score ≥90% / ≥75% / ≥50% |",
        "| **Needs Improvement** | Score ≥25% |",
        "| **Critical Gaps** | Score <25% — immediate remediation required |",
        "",
        "---",
        "",
        "## Profiles Assessed",
        "",
    ]

    for r in all_profile_results:
        lines += [
            f"### {r['label']}",
            "",
            f"*{r['description']}*",
            "",
            f"- **Frameworks assessed:** {r['framework_count']}",
            f"- **Overall score:** {_pct(r['overall_score'])} — {_score_label(r['overall_score'])}",
            f"- **ACGS auto-coverage:** {_pct(r['acgs_coverage'])}",
            f"- **Reports:** [`{r['profile_id']}/`](./{r['profile_id']}/)",
            "",
        ]

    lines += [
        "---",
        "",
        "## All 19 Supported Frameworks",
        "",
        "| ID | Framework | Region/Jurisdiction |",
        "|----|-----------|---------------------|",
    ]

    for fid, desc in sorted(FRAMEWORK_DESCRIPTIONS.items()):
        lines.append(f"| `{fid}` | {desc} | — |")

    lines += [
        "",
        "---",
        "",
        "## File Types",
        "",
        "| Extension | Format | Audience |",
        "|-----------|--------|----------|",
        "| `.txt` | Plain text executive summary | Auditors, legal review |",
        "| `.md` | GitHub Markdown with tables | Developers, GitHub/GitLab |",
        "| `.json` | Machine-readable full detail | CI/CD pipelines, dashboards |",
        "",
        "Per-framework files live in `<profile>/by_framework/<framework_id>.[md|json]`.",
        "",
        "---",
        "",
        "> **Disclaimer:** These are indicative self-assessments only. "
        "They are not legal advice. Consult qualified legal counsel for binding compliance opinions.",
        "",
        "*Generated by acgs-lite · Constitutional Hash: `608508a9bd224290`*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# EXPLAINED.md — field-by-field reference
# ---------------------------------------------------------------------------

_EXPLAINED = """\
# Compliance Report Fields — Explained

This reference covers every field that appears in `.json`, `.md`, and `.txt`
compliance reports generated by `examples/compliance_reports/run.py`.

---

## Top-Level Report Fields (summary.json)

| Field | Type | Meaning |
|-------|------|---------|
| `system_id` | string | Identifier of the assessed AI system |
| `frameworks_assessed` | list | Framework IDs that were evaluated |
| `overall_score` | float | Weighted average compliance score across all frameworks (0.0–1.0) |
| `acgs_lite_total_coverage` | float | Average fraction of requirements auto-satisfied by acgs-lite |
| `cross_framework_gaps` | list | Gap themes that appear in multiple frameworks simultaneously |
| `recommendations` | list | Prioritized actions, highest-impact first |
| `assessed_at` | ISO 8601 | Timestamp of the assessment run |
| `disclaimer` | string | Legal disclaimer (self-assessment, not legal advice) |

---

## Per-Framework Fields (by_framework/<id>.json)

| Field | Type | Meaning |
|-------|------|---------|
| `framework_id` | string | Machine identifier (e.g. `nist_ai_rmf`) |
| `framework_name` | string | Human-readable name (e.g. `NIST AI RMF`) |
| `compliance_score` | float | Fraction of applicable items compliant (0.0–1.0) |
| `acgs_lite_coverage` | float | Fraction auto-satisfied by acgs-lite out of the box |
| `gaps` | list | String descriptions of non-compliant items |
| `recommendations` | list | Framework-specific actionable remediation steps |
| `assessed_at` | ISO 8601 | Timestamp |
| `items` | list | Full checklist (see below) |

---

## Checklist Item Fields (items[] in framework JSON)

| Field | Type | Meaning |
|-------|------|---------|
| `ref` | string | Regulatory reference (e.g. `NIST MAP 1.1`, `GDPR Art.22`) |
| `requirement` | string | Full text of the requirement |
| `status` | enum | `compliant` / `partial` / `non_compliant` / `pending` / `not_applicable` |
| `evidence` | string | What satisfies this requirement (set when compliant) |
| `acgs_lite_feature` | string | Which acgs-lite feature covers this item |
| `blocking` | bool | If `true`, a non-compliant status blocks the compliance gate |
| `legal_citation` | string | Statute / article / section reference |
| `updated_at` | ISO 8601 | When this item was last evaluated |

---

## Status Values

| Status | Meaning | Action |
|--------|---------|--------|
| `compliant` | Requirement is met | None |
| `partial` | Partially met — evidence present but gaps remain | Review gaps |
| `non_compliant` | Requirement is not met | Remediate before deployment |
| `pending` | Not yet evaluated | Schedule evaluation |
| `not_applicable` | Does not apply to this system | Document rationale |

---

## Score Thresholds

| Range | Label | Interpretation |
|-------|-------|----------------|
| ≥ 90% | Excellent | Production-ready posture |
| ≥ 75% | Good | Minor gaps; track to close |
| ≥ 50% | Fair | Moderate gaps; remediate before regulated deployment |
| ≥ 25% | Needs Improvement | Significant gaps; not ready for regulated use |
| < 25% | Critical Gaps | Fundamental controls missing; stop deployment |

---

## ACGS-Lite Coverage

This shows what fraction of each framework's requirements acgs-lite provides
supporting technical measures for — without any configuration beyond a
`Constitution` and `AuditLog`.

High coverage means: deploying acgs-lite already closes most of the compliance
checklist. Remaining gaps typically require organizational controls (policies,
training, incident response plans) outside the scope of a governance library.

---

## Cross-Framework Gaps

Themes that appear as gaps across multiple frameworks simultaneously. Fixing
one cross-framework gap closes requirements in several frameworks at once.

Common themes:
- **bias_testing** — fairness testing required by EU AI Act, NYC LL144, NIST AI RMF
- **data_governance** — lineage and quality required by ISO 42001, GDPR, HIPAA
- **incident_response** — breach notification required by GDPR, HIPAA, DORA, CCPA
- **model_documentation** — technical documentation required by EU AI Act, ISO 42001
- **stakeholder_engagement** — affected population engagement in OECD AI, Australia, Canada AIDA

---

## Disclaimer

All reports are indicative self-assessments only. They are not legal advice.
Consult qualified legal counsel for binding compliance opinions.

*Generated by acgs-lite · Constitutional Hash: `608508a9bd224290`*
"""


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run() -> None:
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    all_profile_results = []

    print("=" * 60)
    print("  ACGS-Lite Compliance Report Generator")
    print("=" * 60)
    print(f"  Output: {REPORTS_DIR.resolve()}")
    print(f"  Generated: {generated_at}")
    print()

    for profile in PROFILES:
        pid = profile["profile_id"]
        label = profile["label"]
        system = dict(profile["system"])
        fw_list = profile["frameworks"]

        print(f"── {label}")

        assessor = MultiFrameworkAssessor(frameworks=fw_list)
        report = assessor.assess(system)

        exporter = ComplianceReportExporter(
            report,
            title=f"ACGS-Lite Compliance Report — {label}",
        )

        out = REPORTS_DIR / pid

        # Master reports in 3 formats
        exporter.to_text_file(out / "summary.txt")
        exporter.to_markdown_file(out / "summary.md")
        exporter.to_json_file(out / "summary.json")

        # Per-framework files (all profiles, not just the all-frameworks one)
        fw_rows = _write_framework_files(report, out)

        score = report.overall_score
        coverage = report.acgs_lite_total_coverage
        n_fw = len(report.frameworks_assessed)

        print(f"   Score: {_pct(score)} — {_score_label(score)}")
        print(f"   Frameworks: {n_fw}  |  ACGS coverage: {_pct(coverage)}")
        print(f"   Files: {out.relative_to(REPORTS_DIR.parent.parent)}/")
        print()

        all_profile_results.append(
            {
                "profile_id": pid,
                "label": label,
                "description": profile["description"],
                "framework_count": n_fw,
                "overall_score": score,
                "acgs_coverage": coverage,
                "fw_rows": fw_rows,
            }
        )

    # Master index and explanation
    _write(REPORTS_DIR / "INDEX.md", _build_index(all_profile_results, generated_at))
    _write(REPORTS_DIR / "EXPLAINED.md", _EXPLAINED)

    # Print file tree
    print("── Generated files")
    for path in sorted(REPORTS_DIR.rglob("*")):
        if path.is_file():
            rel = path.relative_to(REPORTS_DIR)
            indent = "   " + "   " * (len(rel.parts) - 1)
            print(f"{indent}{rel.parts[-1]}")

    print()
    print("  ✅  Done. Open reports/INDEX.md for a guided tour.")
    print("  📄  reports/EXPLAINED.md describes every field in detail.")
    print("=" * 60)


if __name__ == "__main__":
    run()
