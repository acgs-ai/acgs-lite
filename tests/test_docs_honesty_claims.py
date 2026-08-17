"""Guard public docs against unsupported social-proof and simulation claims."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SIMULATION_PREFIX = "SIMULATION (seed=42), not empirical benchmark"

PUBLIC_SURFACES = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "index.md",
    REPO_ROOT / "docs" / "compliance.md",
    REPO_ROOT / "docs" / "cli.md",
    REPO_ROOT / "research" / "README.md",
)

EXPERIMENT_SCRIPTS = tuple(
    REPO_ROOT / "research" / name
    for name in (
        "x1_constitutional_humaneval.py",
        "x2_swe_secrets.py",
        "x3_maci_decisions.py",
        "x4_maci_latency.py",
        "x5_prov_export.py",
        "x6_diff_audit.py",
    )
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_banned_public_social_proof_strings_absent() -> None:
    banned_strings = (
        "Featured in " + "Awesome " + "LLM " + "Security",
        "Community " + "favorites",
        "most " + "shared",
    )
    offenders = []
    for path in PUBLIC_SURFACES:
        text = _read(path)
        for banned in banned_strings:
            if banned in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {banned!r}")

    assert not offenders, "unsupported public social-proof claims remain: " + ", ".join(offenders)


def test_readme_does_not_tell_pip_users_to_run_repo_examples() -> None:
    readme = _read(REPO_ROOT / "README.md")
    examples_readme = _read(REPO_ROOT / "examples" / "README.md")
    offenders = []
    for label, text in (("README.md", readme), ("examples/README.md", examples_readme)):
        if re.search(r"pip install acgs-lite(?:==[0-9.]+)?\s*\npython examples/", text):
            offenders.append(label)
    assert not offenders, (
        "pip-only users cannot run repo example paths; offenders: " + ", ".join(offenders)
    )


def test_readme_hero_uses_fail_closed_default_engine() -> None:
    readme = _read(REPO_ROOT / "README.md")
    match = re.search(r"```python\n(.*?)```", readme, flags=re.DOTALL)
    assert match, "README has no python hero block"
    hero = match.group(1)
    assert "GovernanceEngine" in hero
    assert "strict=False" not in hero
    assert "wire transfer" in hero


def test_readme_compliance_ratios_are_self_assessed() -> None:
    ratio_pattern = re.compile(r"\|\s*\*\*[^|]+\*\*.*\|\s*\d+/\d+\s*\|")
    offenders = []
    for line_number, line in enumerate(_read(REPO_ROOT / "README.md").splitlines(), start=1):
        if ratio_pattern.search(line) and "SELF-ASSESSED mapping coverage" not in line:
            offenders.append(f"README.md:{line_number}: {line}")
    assert not offenders, "unlabeled README compliance ratios remain:\n" + "\n".join(offenders)


def test_example_readmes_state_prove_and_non_claims() -> None:
    required = ("## What this proves", "## What this does not claim")
    paths = (
        REPO_ROOT / "examples" / "basic_governance" / "README.md",
        REPO_ROOT / "examples" / "audit_trail" / "README.md",
        REPO_ROOT / "examples" / "agent_quickstart" / "README.md",
    )
    offenders = []
    for path in paths:
        text = _read(path)
        missing = [heading for heading in required if heading not in text]
        if missing:
            offenders.append(f"{path.relative_to(REPO_ROOT)} missing {missing}")
        if re.search(r"pip install acgs-lite(?:==[0-9.]+)?\s*\npython examples/", text):
            offenders.append(f"{path.relative_to(REPO_ROOT)} pip+examples first-run")
    assert not offenders, "example README honesty gaps:\n" + "\n".join(offenders)


def test_five_minute_guide_states_fail_closed_refusals() -> None:
    guide = _read(REPO_ROOT / "docs" / "guides" / "five-minute-membrane.md")
    assert "No legitimacy receipt, no execution" in guide
    assert "Decision DENY_GOAL does not permit execution" in guide
    assert "What this does not claim" in guide
    assert "examples/` is **not** shipped on PyPI" in guide or "not** shipped on PyPI" in guide


def test_empty_production_users_table_is_reframed() -> None:
    readme = _read(REPO_ROOT / "README.md")
    placeholder_row = "| *(" + "your " + "org here" + ")*"

    assert "No independently confirmed production users yet." in readme
    assert placeholder_row not in readme
    assert ("Used in " + "production at...") not in readme


def test_compliance_ratios_are_self_assessed_mapping_coverage() -> None:
    ratio_pattern = re.compile(r"\|\s*\*\*[^|]+\*\*.*\|\s*\d+/\d+\s*\|")
    docs = (REPO_ROOT / "docs" / "index.md", REPO_ROOT / "docs" / "compliance.md")
    offenders = []

    for path in docs:
        for line_number, line in enumerate(_read(path).splitlines(), start=1):
            if ratio_pattern.search(line) and "SELF-ASSESSED mapping coverage" not in line:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_number}: {line}")

    assert not offenders, "unlabeled compliance mapping ratios remain: " + "\n".join(offenders)


def test_homepage_compliance_table_leads_with_coverage_not_penalties() -> None:
    index = _read(REPO_ROOT / "docs" / "index.md")

    assert "| Framework | Mapping Coverage | Review Context |" in index
    assert "| Framework | Business Risk | Mapping Coverage |" not in index
    assert "$1.5M fine per violation" not in index
    assert "penalty exposure is tiered and inflation-adjusted" in index


def test_acgs_verify_docs_do_not_claim_constitutional_hash_validation() -> None:
    cli = _read(REPO_ROOT / "docs" / "cli.md")
    cli_normalized = " ".join(cli.split())

    assert "acgs verify                 Validate license key integrity only" in _read(
        REPO_ROOT / "src" / "acgs_lite" / "cli.py"
    )
    assert "Validate the integrity of your license key and constitutional hash." not in cli
    assert "does not validate constitutional hash integrity" in cli_normalized


def test_research_result_lines_are_simulation_prefixed() -> None:
    text = _read(REPO_ROOT / "research" / "README.md")
    result_block = text.split("## Experiment Results (seed=42)", maxsplit=1)[1].split(
        "## Compliance Anchors",
        maxsplit=1,
    )[0]

    offenders = [
        line
        for line in result_block.splitlines()
        if line.startswith("- ") and not line.startswith(f"- {SIMULATION_PREFIX}")
    ]

    assert not offenders, "research result lines missing simulation prefix: " + "\n".join(offenders)


def test_experiment_generators_emit_simulation_metadata() -> None:
    offenders = []
    for path in EXPERIMENT_SCRIPTS:
        text = _read(path)
        if '"simulation"' not in text or "not empirical benchmark" not in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, "experiment outputs lack simulation metadata: " + ", ".join(offenders)
