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

    assert not offenders, "unsupported public social-proof claims remain: " + ", ".join(
        offenders
    )


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

    assert not offenders, "unlabeled compliance mapping ratios remain: " + "\n".join(
        offenders
    )


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

    assert not offenders, "research result lines missing simulation prefix: " + "\n".join(
        offenders
    )


def test_experiment_generators_emit_simulation_metadata() -> None:
    offenders = []
    for path in EXPERIMENT_SCRIPTS:
        text = _read(path)
        if '"simulation"' not in text or "not empirical benchmark" not in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, "experiment outputs lack simulation metadata: " + ", ".join(
        offenders
    )
