from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).parents[1] / "scripts" / "release_candidate.py"
SPEC = importlib.util.spec_from_file_location("release_candidate", SCRIPT)
assert SPEC and SPEC.loader
release_candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_candidate)


def test_release_qualification_installs_required_crypto_extra() -> None:
    workflow = yaml.safe_load(
        (SCRIPT.parents[1] / ".github/workflows/release-candidate.yml").read_text()
    )
    bridge_install = next(
        step["run"]
        for step in workflow["jobs"]["gove-compatibility"]["steps"]
        if step.get("name") == "Install declared optional combination"
    )
    wheel_install = next(
        step["run"]
        for step in workflow["jobs"]["qualify"]["steps"]
        if step.get("name") == "Install exact wheel in clean environment"
    )
    assert '".[gove,crypto]"' in bridge_install
    assert '"${1}[z3,gove,crypto]"' in wheel_install


@pytest.mark.parametrize(
    ("status", "curl_exit", "allowed"),
    [
        (404, 0, True),
        (200, 0, False),
        (500, 0, False),
        (301, 0, False),
        (0, 7, False),
        (0, 35, False),
        (404, 7, False),
        (0, 28, False),
    ],
)
def test_publish_version_lookup_fails_closed(
    tmp_path: Path, status: int, curl_exit: int, allowed: bool
) -> None:
    workflow = yaml.safe_load((SCRIPT.parents[1] / ".github/workflows/publish.yml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["publish"]["steps"]
        if item.get("name") == "Refuse an already published version"
    )
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > curl-args.txt\n"
        "fail=0; write=0\n"
        'for arg in "$@"; do\n'
        '  case "$arg" in --fail|-f) fail=1;; --write-out|-w) write=1;; esac\n'
        "done\n"
        'if [ "$write" = 1 ]; then printf \'%03d\' "$CURL_STATUS"; fi\n'
        'if [ "$CURL_EXIT" != 0 ]; then exit "$CURL_EXIT"; fi\n'
        'if [ "$fail" = 1 ] && [ "$CURL_STATUS" -ge 400 ]; then exit 22; fi\n'
        "exit 0\n"
    )
    curl.chmod(0o755)
    environment = dict(
        os.environ,
        PATH=f"{tmp_path}:{os.environ['PATH']}",
        TAG="v2.13.0",
        CURL_STATUS=str(status),
        CURL_EXIT=str(curl_exit),
    )
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr
    arguments = (tmp_path / "curl-args.txt").read_text().splitlines()
    assert arguments[arguments.index("--connect-timeout") + 1] == "10"
    assert arguments[arguments.index("--max-time") + 1] == "30"


def test_local_manifest_includes_mode_and_publish_rejects_local(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    product = source / "tool.py"
    product.write_text("print('ok')\n", encoding="utf-8")
    product.chmod(0o755)
    artifact = tmp_path / "acgs_lite-2.12.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel")
    qualification = {
        "schema": "acgs-lite-qualification-v1",
        "status": "PASS_WITHIN_STATED_SCOPE",
        "version": "2.12.0",
    }

    manifest = release_candidate.create_manifest(
        source_root=source,
        source_paths=[Path("tool.py")],
        artifacts=[artifact],
        provenance="local-uncommitted",
        source_ref="working-tree",
        source_sha="abc",
        qualification=qualification,
    )

    assert manifest["source_files"] == [
        {
            "path": "tool.py",
            "mode": "100755",
            "sha256": release_candidate.sha256_file(product),
        }
    ]
    with pytest.raises(ValueError, match="local-uncommitted"):
        release_candidate.verify_manifest(manifest, tmp_path, for_publish=True)


def test_verify_rejects_artifact_and_qualification_binding_mismatch(tmp_path: Path) -> None:
    artifact = tmp_path / "acgs_lite-2.13.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel")
    qualification = {
        "schema": "acgs-lite-qualification-v1",
        "status": "PASS_WITHIN_STATED_SCOPE",
        "version": "2.13.0",
        "source_sha": "abc",
    }
    manifest = release_candidate.create_manifest(
        source_root=tmp_path,
        source_paths=[],
        artifacts=[artifact],
        provenance="git",
        source_ref="refs/tags/v2.13.0",
        source_sha="abc",
        qualification=qualification,
    )
    release_candidate.verify_manifest(manifest, tmp_path)

    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="artifact digest"):
        release_candidate.verify_manifest(manifest, tmp_path)

    artifact.write_bytes(b"wheel")
    manifest["qualification"]["source_sha"] = "different"
    with pytest.raises(ValueError, match="qualification source"):
        release_candidate.verify_manifest(manifest, tmp_path)


def test_publish_metadata_is_exact_and_fresh(tmp_path: Path) -> None:
    artifact = tmp_path / "acgs_lite-2.13.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel")
    manifest = release_candidate.create_manifest(
        source_root=tmp_path,
        source_paths=[],
        artifacts=[artifact],
        provenance="git",
        source_ref="refs/tags/v2.13.0",
        source_sha="abc",
        qualification={
            "schema": "acgs-lite-qualification-v1",
            "status": "PASS_WITHIN_STATED_SCOPE",
            "version": "2.13.0",
            "source_sha": "abc",
            "repository": "acgs-ai/acgs-lite",
            "workflow_path": ".github/workflows/release-candidate.yml",
            "event_name": "workflow_dispatch",
            "head_repository": "acgs-ai/acgs-lite",
            "run_id": "123",
            "run_attempt": 1,
            "conclusion": "success",
            "created_at": "2026-09-17T12:00:00Z",
        },
    )
    expected = {
        "repository": "acgs-ai/acgs-lite",
        "workflow_path": ".github/workflows/release-candidate.yml",
        "event_name": "workflow_dispatch",
        "head_repository": "acgs-ai/acgs-lite",
        "run_id": "123",
        "source_ref": "refs/tags/v2.13.0",
    }
    release_candidate.verify_publish_metadata(
        manifest,
        expected,
        now="2026-09-17T13:00:00Z",
        max_age_hours=24,
    )
    expected["run_id"] = "124"
    with pytest.raises(ValueError, match="run_id"):
        release_candidate.verify_publish_metadata(
            manifest,
            expected,
            now="2026-09-17T13:00:00Z",
            max_age_hours=24,
        )
    expected["run_id"] = "123"
    run = {
        "id": 123,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/release-candidate.yml",
        "head_sha": "abc",
        "created_at": "2026-09-17T12:00:00Z",
        "repository": {"full_name": "acgs-ai/acgs-lite"},
        "head_repository": {"full_name": "acgs-ai/acgs-lite"},
    }
    with pytest.raises(ValueError, match="stale"):
        release_candidate.verify_run_metadata(
            manifest, run, now="2026-09-19T13:00:01Z", max_age_hours=24
        )


def test_cli_round_trip_rejects_recursive_manifest(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    artifact = tmp_path / "pkg.whl"
    artifact.write_bytes(b"wheel")
    output = source / "candidate.json"
    qualification = tmp_path / "qualification.json"
    qualification.write_text(
        json.dumps(
            {
                "schema": "acgs-lite-qualification-v1",
                "status": "PASS_WITHIN_STATED_SCOPE",
                "version": "2.13.0",
            }
        ),
        encoding="utf-8",
    )
    assert (
        release_candidate.main(
            [
                "create",
                "--source-root",
                os.fspath(source),
                "--output",
                os.fspath(output),
                "--artifact",
                os.fspath(artifact),
                "--qualification",
                os.fspath(qualification),
                "--provenance",
                "local-uncommitted",
                "--source-ref",
                "working-tree",
                "--source-sha",
                "abc",
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert all(item["path"] != "candidate.json" for item in payload["source_files"])


def test_source_file_set_and_evidence_are_exact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "tracked.py").write_text("x = 1\n", encoding="utf-8")
    artifact = tmp_path / "pkg.whl"
    artifact.write_bytes(b"wheel")
    evidence = []
    for name in (
        "tests.xml",
        "coverage.json",
        "wheel-qualification.json",
        "qualification.json",
    ):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        evidence.append(path)
    qualification = {
        "schema": "acgs-lite-qualification-v1",
        "status": "PASS_WITHIN_STATED_SCOPE",
        "wheel_status": "PASS_WITHIN_STATED_SCOPE",
        "coverage_status": "PASS_WITHIN_STATED_SCOPE",
        "source_suite_status": "PASS_WITHIN_STATED_SCOPE",
        "version": "2.13.0",
        "source_sha": "abc",
    }
    manifest = release_candidate.create_manifest(
        source_root=source,
        source_paths=[Path("tracked.py")],
        artifacts=[artifact],
        evidence=evidence,
        provenance="local-uncommitted",
        source_ref="working-tree",
        source_sha="abc",
        qualification=qualification,
    )
    release_candidate.verify_manifest(manifest, tmp_path, source_root=source)
    (source / "omitted.py").write_text("x = 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="file set"):
        release_candidate.verify_manifest(manifest, tmp_path, source_root=source)
    (source / "omitted.py").unlink()
    evidence[0].write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="evidence digest"):
        release_candidate.verify_manifest(manifest, tmp_path)


def test_fetched_run_must_match_self_recorded_provenance(tmp_path: Path) -> None:
    artifact = tmp_path / "pkg.whl"
    artifact.write_bytes(b"wheel")
    manifest = release_candidate.create_manifest(
        source_root=tmp_path,
        source_paths=[],
        artifacts=[artifact],
        provenance="git",
        source_ref="refs/tags/v2.13.0",
        source_sha="abc",
        qualification={
            "status": "PASS_WITHIN_STATED_SCOPE",
            "source_sha": "abc",
            "repository": "acgs-ai/acgs-lite",
            "workflow_path": ".github/workflows/release-candidate.yml",
            "run_id": "123",
            "run_attempt": 2,
        },
    )
    run = {
        "id": 123,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "path": ".github/workflows/release-candidate.yml",
        "head_sha": "abc",
        "created_at": "2026-09-17T12:00:00Z",
        "repository": {"full_name": "acgs-ai/acgs-lite"},
        "head_repository": {"full_name": "acgs-ai/acgs-lite"},
    }
    with pytest.raises(ValueError, match="run_attempt"):
        release_candidate.verify_run_metadata(manifest, run, now="2026-09-17T13:00:00Z")


def test_git_provenance_rejects_dirty_checkout(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
    (source / "tracked.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.py"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=source, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True
    ).stdout.strip()
    (source / "dirty.py").write_text("x = 2\n", encoding="utf-8")
    artifact = tmp_path / "pkg.whl"
    artifact.write_bytes(b"wheel")
    qualification = tmp_path / "qualification.json"
    qualification.write_text(
        json.dumps({"status": "PASS_WITHIN_STATED_SCOPE", "version": "2.13.0"}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="clean checkout"):
        release_candidate.main(
            [
                "create",
                "--source-root",
                os.fspath(source),
                "--output",
                os.fspath(tmp_path / "candidate.json"),
                "--artifact",
                os.fspath(artifact),
                "--qualification",
                os.fspath(qualification),
                "--provenance",
                "git",
                "--source-ref",
                "HEAD",
                "--source-sha",
                head,
            ]
        )
