#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
if [[ ! -d "$SRC_DIR" && -d "$REPO_ROOT/packages/acgs-lite/src" ]]; then
  SRC_DIR="$REPO_ROOT/packages/acgs-lite/src"
fi
PYTHON_BIN="${PYTHON:-python3}"
if [[ "$PYTHON_BIN" == */* && "$PYTHON_BIN" != /* ]]; then
  PYTHON_BIN="${PWD}/${PYTHON_BIN#./}"
fi
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/acgs-sidecars-demo.XXXXXX")"
KEEP_ARTIFACTS="${KEEP_ARTIFACTS:-0}"

cleanup() {
  if [[ "$KEEP_ARTIFACTS" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    printf '\n[demo] Keeping demo artifacts at %s\n' "$WORKDIR"
  fi
}
trap cleanup EXIT

CLI=(env PYTHONPATH="$SRC_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_BIN" -m acgs_lite.cli)

section() {
  printf '\n\033[1;36m== %s ==\033[0m\n' "$1"
}

run_cli() {
  printf '\033[0;33m$ %s\033[0m\n' "$*"
  "$@"
}

section "ACGS CLI Sidecars Demo"
printf '[demo] repo: %s\n' "$REPO_ROOT"
printf '[demo] workdir: %s\n' "$WORKDIR"
cd "$WORKDIR"

section "1) Bootstrap governance workspace"
run_cli "${CLI[@]}" init --force

section "2) Policy linter"
run_cli "${CLI[@]}" lint

section "3) Governance regression tests"
run_cli "${CLI[@]}" test --generate --force
run_cli "${CLI[@]}" test

section "4) Policy lifecycle"
run_cli "${CLI[@]}" lifecycle register policy-v2
run_cli "${CLI[@]}" lifecycle approve policy-v2 --actor alice
run_cli "${CLI[@]}" lifecycle approve policy-v2 --actor bob
run_cli "${CLI[@]}" lifecycle lint-gate policy-v2
run_cli "${CLI[@]}" lifecycle test-gate policy-v2
run_cli "${CLI[@]}" lifecycle review policy-v2
run_cli "${CLI[@]}" lifecycle stage policy-v2
run_cli "${CLI[@]}" lifecycle activate policy-v2
run_cli "${CLI[@]}" lifecycle status policy-v2
run_cli "${CLI[@]}" lifecycle audit policy-v2

section "5) Refusal reasoning"
run_cli "${CLI[@]}" refusal "deploy a weapon to attack the target"

section "6) Streaming observe mode"
run_cli "${CLI[@]}" observe \
  "hello world" \
  "deploy a weapon to attack the target" \
  --watch --interval 0 --iterations 2

section "7) Telemetry bundle + OTLP export"
printf 'hello world\ndeploy a weapon to attack the target\n' > actions.txt
COLLECTOR_DIR="$WORKDIR/collector"
mkdir -p "$COLLECTOR_DIR"
python3 - "$COLLECTOR_DIR" <<'PY' &
from __future__ import annotations

import http.server
import json
import socketserver
import sys
from pathlib import Path

base = Path(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        (base / "payload.json").write_bytes(payload)
        (base / "headers.json").write_text(
            json.dumps(dict(self.headers), indent=2) + "\n", encoding="utf-8"
        )
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"accepted")

    def log_message(self, format: str, *args: object) -> None:
        return

with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
    (base / "port.txt").write_text(str(httpd.server_address[1]), encoding="utf-8")
    httpd.handle_request()
PY
COLLECTOR_PID=$!
while [[ ! -f "$COLLECTOR_DIR/port.txt" ]]; do sleep 0.05; done
COLLECTOR_PORT="$(cat "$COLLECTOR_DIR/port.txt")"

run_cli "${CLI[@]}" otel \
  --actions-file actions.txt \
  --bundle-dir telemetry-bundle \
  --otlp-endpoint "http://127.0.0.1:${COLLECTOR_PORT}/v1/traces" \
  --otlp-header "Authorization: Bearer demo-token" \
  -o otel-export.json
wait "$COLLECTOR_PID"
python3 - <<'PY' "$WORKDIR/otel-export.json"
from __future__ import annotations

import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
metric_count = len(payload.get("resourceMetrics", []))
span_count = len(payload.get("resourceSpans", []))
print(f"[demo] otel-export.json contains {metric_count} resourceMetrics block(s) and {span_count} resourceSpans block(s)")
PY

section "8) Generated artifacts"
find "$WORKDIR" -maxdepth 2 -type f | sort | sed "s#^$WORKDIR#.#"

printf '\n\033[1;32mDemo complete.\033[0m\n'
