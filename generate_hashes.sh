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

python3 - <<PY > hash_verify.log
from datetime import datetime, timezone

from monsterboy_aegis_modules.audit import verify_replay_artifacts

run_dir = "$RUN_DIR"
hash_file = "$HASH_FILE"
verification = verify_replay_artifacts(run_dir, hash_file)

phase_3_status = "READY_LOCAL_REPLAY" if verification["checks_failed"] == 0 else "SAFE_HOLD"
delta_maglo_verdict = (
    "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY"
    if verification["checks_failed"] == 0
    else "FAIL_CLOSED"
)

print(f"generated_at_utc={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
print("mode=FAIL_CLOSED")
print(f"phase_3_status={phase_3_status}")
print("delta_maglo_rc=rc3.2.1")
print(f"delta_maglo_verdict={delta_maglo_verdict}")
print("global_ceiling=LAB_ONLY")
print(f"run_directory={run_dir}")
print(f"hash_file={hash_file}")
print(f"checks_passed={verification['checks_passed']}")
print(f"checks_failed={verification['checks_failed']}")
print(f"verdict={verification['status']}")
for check in verification["checks"]:
    print(f"{check['name']}={check['status']}")
PY

cat "$HASH_FILE" >> hash_verify.log

echo "$HASH_FILE"
