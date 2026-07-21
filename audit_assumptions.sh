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
hash_verify_data = {}
hash_verify_path = Path("hash_verify.log")
if hash_verify_path.is_file():
    for line in hash_verify_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        hash_verify_data[key] = value

checks = {
    "stdout_log_exists": (run_dir / "stdout.log").is_file(),
    "environment_json_exists": (run_dir / "environment.json").is_file(),
    "result_json_exists": (run_dir / "result.json").is_file(),
    "execution_manifest_exists": (run_dir / "execution_manifest.json").is_file(),
    "hash_verify_log_exists": hash_verify_path.is_file(),
    "hash_verify_checks_failed_zero": hash_verify_data.get("checks_failed") == "0",
    "phase_3_status_ready_local_replay": hash_verify_data.get("phase_3_status") == "READY_LOCAL_REPLAY",
    "delta_maglo_local_dual_runtime_recompute_only": hash_verify_data.get("delta_maglo_verdict") == "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY",
    "global_ceiling_lab_only": hash_verify_data.get("global_ceiling") == "LAB_ONLY",
}
all_pass = all(checks.values())
out = {
    "audited_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run_directory": str(run_dir),
    "checks": checks,
    "verdict": "PASS_LOCAL_ONLY" if all_pass else "FAIL_CLOSED",
    "phase_3_status": hash_verify_data.get("phase_3_status", "SAFE_HOLD"),
    "delta_maglo_rc": hash_verify_data.get("delta_maglo_rc", "rc3.2.1"),
    "delta_maglo_verdict": hash_verify_data.get("delta_maglo_verdict", "FAIL_CLOSED"),
    "global_ceiling": hash_verify_data.get("global_ceiling", "LAB_ONLY"),
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
print(f"phase_3_status={audit['phase_3_status']}")
print(f"delta_maglo_rc={audit['delta_maglo_rc']}")
print(f"delta_maglo_verdict={audit['delta_maglo_verdict']}")
print(f"global_ceiling={audit['global_ceiling']}")
PY

echo "$AUDIT_JSON"
