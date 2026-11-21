#!/usr/bin/env bash
# requires: Lean 4 / lake toolchain, ACGS_LEAN_WORKDIR, <lean-file> arg
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: lean-wrapper.sh <lean-file>" >&2
  exit 2
fi

: "${ACGS_LEAN_WORKDIR:?ACGS_LEAN_WORKDIR must point to a Lean/Lake project}"
cd "$ACGS_LEAN_WORKDIR"

exec lake env lean "$@"
