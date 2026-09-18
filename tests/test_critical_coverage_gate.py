from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_critical_coverage.py"


def _write_report(path: Path, *, critical_percent: float, auth_percent: float) -> None:
    from scripts.check_critical_coverage import CRITICAL_FILES, GOVERNED_AUTH_FILES

    files = {}
    for name in CRITICAL_FILES:
        percent = auth_percent if name in GOVERNED_AUTH_FILES else critical_percent
        files[f"src/acgs_lite/{name}"] = {
            "summary": {
                "covered_lines": int(percent),
                "num_statements": 100,
            }
        }
    path.write_text(json.dumps({"files": files}), encoding="utf-8")


def test_gate_accepts_both_thresholds(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    _write_report(report, critical_percent=95, auth_percent=91)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(report)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert 'critical="' not in result.stdout
    assert "critical=" in result.stdout


def test_gate_rejects_low_auth_or_missing_file(tmp_path: Path) -> None:
    low = tmp_path / "low.json"
    _write_report(low, critical_percent=95, auth_percent=89)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(low)], cwd=ROOT, text=True, capture_output=True
    )
    assert result.returncode != 0
    assert "governed+legitimacy" in result.stderr

    payload = json.loads(low.read_text(encoding="utf-8"))
    payload["files"].pop(next(iter(payload["files"])))
    low.write_text(json.dumps(payload), encoding="utf-8")
    missing = subprocess.run(
        [sys.executable, str(SCRIPT), str(low)], cwd=ROOT, text=True, capture_output=True
    )
    assert missing.returncode != 0
    assert "missing coverage data" in missing.stderr
