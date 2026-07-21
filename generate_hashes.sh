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
PY_HASH_FILE="replay_outputs/$(basename "$RUN_DIR")_sha256_py.txt"

FILES=(
  "$RUN_DIR/stdout.log"
  "$RUN_DIR/environment.json"
  "$RUN_DIR/result.json"
  "$RUN_DIR/execution_manifest.json"
)

sha256sum "${FILES[@]}" > "$HASH_FILE"

python3 - "${FILES[@]}" <<'PY' > "$PY_HASH_FILE"
import hashlib
import sys
from pathlib import Path

for raw_path in sys.argv[1:]:
    path = Path(raw_path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{digest}  {raw_path}")
PY

if ! cmp -s "$HASH_FILE" "$PY_HASH_FILE"; then
  echo "ERROR: dual-runtime hash recompute mismatch (sha256sum vs python hashlib)." >&2
  exit 1
fi

{
  echo "generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode=FAIL_CLOSED"
  echo "phase3_status=READY_LOCAL_REPLAY"
  echo "claim_ceiling=LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY"
  echo "delta_maglo_claim=LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY"
  echo "global_claim_ceiling=LAB_ONLY"
  echo "checks_failed=0"
  echo "dual_runtime_recompute_pass=true"
  echo "run_directory=$RUN_DIR"
  echo "hash_file=$HASH_FILE"
  echo "python_hash_file=$PY_HASH_FILE"
  cat "$HASH_FILE"
} > hash_verify.log

echo "$HASH_FILE"
