#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${1:-$(ls -1d real_contact_logs/run_* 2>/dev/null | sort | tail -n1)}"
if [[ -z "${RUN_DIR:-}" || ! -d "$RUN_DIR" ]]; then
  echo "ERROR: No run directory found." >&2
  exit 1
fi

mkdir -p replay_outputs
HASH_FILE="replay_outputs/$(basename "$RUN_DIR")_sha256.txt"

sha256sum \
  "$RUN_DIR/stdout.log" \
  "$RUN_DIR/environment.json" \
  "$RUN_DIR/result.json" \
  "$RUN_DIR/execution_manifest.json" > "$HASH_FILE"

{
  echo "generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode=FAIL_CLOSED"
  echo "claim_ceiling=STRUCTURAL_LOCAL_ONLY"
  echo "run_directory=$RUN_DIR"
  echo "hash_file=$HASH_FILE"
  cat "$HASH_FILE"
} > hash_verify.log

echo "$HASH_FILE"
