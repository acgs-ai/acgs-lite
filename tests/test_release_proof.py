from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from acgs_lite import __version__


def test_release_proof_script_emits_json(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_path = tmp_path / "release-proof.json"

    completed = subprocess.run(
        [sys.executable, str(repo_root / "examples" / "release_proof.py"), "--output", str(output_path)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload["release"] == __version__
    assert payload["summary"]["decisions"] == ["ALLOW", "TRANSFORM", "DENY"]
    assert payload["summary"]["executed_side_effects"] == 2
    assert payload["summary"]["denied_execution_blocked"] is True
    assert payload["summary"]["receiptless_execution_blocked"] is True
    assert payload["summary"]["audit_chain_valid"] is True
    assert completed.stdout.strip().startswith("{")
