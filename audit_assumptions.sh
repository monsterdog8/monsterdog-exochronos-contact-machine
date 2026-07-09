#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_DIR="${1:-$(ls -1d real_contact_logs/run_* 2>/dev/null | sort | tail -n1)}"
if [[ -z "${RUN_DIR:-}" || ! -d "$RUN_DIR" ]]; then
  echo "ERROR: No run directory found." >&2
  exit 1
fi

mkdir -p audit_outputs
AUDIT_JSON="audit_outputs/$(basename "$RUN_DIR")_assumption_audit.json"

python3 - <<PY > "$AUDIT_JSON"
import json
from datetime import datetime, timezone
from pathlib import Path

run_dir = Path("$RUN_DIR")
checks = {
    "stdout_log_exists": (run_dir / "stdout.log").is_file(),
    "environment_json_exists": (run_dir / "environment.json").is_file(),
    "result_json_exists": (run_dir / "result.json").is_file(),
    "execution_manifest_exists": (run_dir / "execution_manifest.json").is_file(),
    "hash_verify_log_exists": Path("hash_verify.log").is_file(),
}
all_pass = all(checks.values())
out = {
    "audited_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run_directory": str(run_dir),
    "checks": checks,
    "verdict": "PASS_LOCAL_ONLY" if all_pass else "FAIL_CLOSED",
    "claim_ceiling": "STRUCTURAL_LOCAL_ONLY" if all_pass else "NONE",
}
print(json.dumps(out, indent=2, sort_keys=True))
PY

python3 - <<PY > FORENSIC_AUDIT.log
import json
from pathlib import Path

audit = json.loads(Path("$AUDIT_JSON").read_text())
print(f"audited_at_utc={audit['audited_at_utc']}")
print(f"run_directory={audit['run_directory']}")
for k, v in audit["checks"].items():
    print(f"{k}={'PASS' if v else 'FAIL'}")
print(f"verdict={audit['verdict']}")
print(f"claim_ceiling={audit['claim_ceiling']}")
PY

echo "$AUDIT_JSON"
