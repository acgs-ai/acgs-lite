# Compliance Reports

Generates organized, human-readable compliance reports for AI systems across all 20
regulatory frameworks supported by acgs-lite's built-in compliance engine.

```bash
python examples/compliance_reports/run.py
```

No API keys required. All assessments run fully offline.

---

## Output Structure

```
reports/
├── INDEX.md              — master summary: all profiles, scores, and file map
├── EXPLAINED.md          — field-by-field reference for every report format
├── all_frameworks/       — 20-framework sweep, general AI system
│   ├── summary.txt       — plain-text executive summary (auditors, legal review)
│   ├── summary.md        — Markdown with tables and status badges
│   ├── summary.json      — full machine-readable report (CI/CD, dashboards)
│   └── by_framework/
│       ├── eu_ai_act.md        — EU AI Act detail + checklist
│       ├── eu_ai_act.json
│       ├── nist_ai_rmf.md
│       ├── nist_ai_rmf.json
│       └── … (20 frameworks total)
├── healthcare/           — clinical decision-support AI (HIPAA, GDPR, NIST…)
│   ├── summary.txt / .md / .json
│   └── by_framework/
├── financial/            — fraud-detection AI (DORA, SOC 2, Fair Lending…)
│   ├── summary.txt / .md / .json
│   └── by_framework/
└── hr_recruitment/       — CV-screener AI (EU AI Act high-risk, NYC LL144…)
    ├── summary.txt / .md / .json
    └── by_framework/
```

> The `reports/` directory is gitignored. Re-run `run.py` to regenerate.
> `run.py` also writes `reports/EXPLAINED.md`, which defines every field —
> read it after the first run.

---

## System Profiles

| Profile | Domain | Frameworks |
|---------|--------|-----------|
| `all_frameworks` | General-purpose AI | All 20 |
| `healthcare` | Clinical decision support | HIPAA, GDPR, NIST AI RMF, ISO 42001, OECD AI |
| `financial` | Fraud detection | DORA, SOC 2, NIST AI RMF, US Fair Lending, OECD AI, CCPA/CPRA |
| `hr_recruitment` | CV screening (EU high-risk) | EU AI Act, GDPR, ISO 42001, OECD AI |

Framework selection for profiles other than `all_frameworks` is automatic, driven by
the `jurisdiction` and `domain` keys in each system descriptor.

---

## Supported Frameworks (20)

| Framework ID | Name |
|---|---|
| `nist_ai_rmf` | NIST AI Risk Management Framework |
| `iso_42001` | ISO 42001 AI Management System |
| `gdpr` | EU General Data Protection Regulation |
| `eu_ai_act` | EU AI Act (Regulation 2024/1689) |
| `dora` | EU Digital Operational Resilience Act |
| `soc2_ai` | SOC 2 with AI Controls |
| `hipaa_ai` | HIPAA Healthcare AI |
| `us_fair_lending` | US Fair Lending (ECOA/FCRA) |
| `nyc_ll144` | NYC Local Law 144 — Employment AI |
| `oecd_ai` | OECD AI Principles |
| `canada_aida` | Canada AIDA (Bill C-27) |
| `singapore_maigf` | Singapore Model AI Governance Framework |
| `uk_ai_framework` | UK AI White Paper Principles |
| `india_dpdp` | India DPDP Act 2023 |
| `australia_ai_ethics` | Australia 8-Principle AI Ethics Framework |
| `brazil_lgpd` | Brazil LGPD + Automated Decisions |
| `china_ai` | China Algorithmic/GenAI + PIPL |
| `ccpa_cpra` | California CCPA/CPRA |
| `igaming` | iGaming / Online Gambling AI |
| `japan_ai_guidelines` | Japan AI Guidelines for Business (METI/MIC) |

---

## Customizing Profiles

Open `run.py` and edit the `PROFILES` list to add your own system descriptor.
The `system` dict keys that drive framework selection:

```python
{
    "system_id": "your-system-id",
    "domain": "healthcare",          # triggers hipaa_ai
    "jurisdiction": "european_union",# triggers gdpr, eu_ai_act, iso_42001, oecd_ai
    "has_human_oversight": True,
    "has_audit_log": True,
    "has_risk_management": False,
    "has_data_governance": False,
    "processes_personal_data": True,
}
```

Pass `frameworks=["eu_ai_act", "iso_42001"]` to `MultiFrameworkAssessor` for an
explicit framework list, or `frameworks=None` for automatic selection.

---

> **Disclaimer:** These are indicative self-assessments only.
> Not legal advice. Consult qualified legal counsel for binding compliance opinions.
>
> Constitutional Hash: `608508a9bd224290`
