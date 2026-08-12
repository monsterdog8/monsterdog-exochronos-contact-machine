#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path

runs = sorted(Path("real_contact_logs").glob("run_*"))
run_dir = runs[-1] if runs else None
hash_verify_path = Path("hash_verify.log")
dual_runtime_recompute_pass = False

if hash_verify_path.is_file():
    for line in hash_verify_path.read_text().splitlines():
        if line.strip().lower() == "dual_runtime_recompute_pass=true":
            dual_runtime_recompute_pass = True
            break

required = {
    "hash_verify.log": hash_verify_path.is_file(),
    "dual_runtime_recompute_pass": dual_runtime_recompute_pass,
    "FORENSIC_AUDIT.log": Path("FORENSIC_AUDIT.log").is_file(),
    "run_directory_present": run_dir is not None,
}
checks_failed = sum(1 for ok in required.values() if not ok)
all_ok = checks_failed == 0

report = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mode": "FAIL_CLOSED",
    "run_directory": str(run_dir) if run_dir else None,
    "required_evidence_checks": required,
    "checks_failed": checks_failed,
    "risk_substitution": {
        "simulated_output_risk": "mitigated_by_observable_artifacts",
        "missing_artifact_risk": "fail_closed_if_detected",
        "external_validation_risk": "not_claimed",
    },
    "verdict": "PASS_LOCAL_ONLY" if all_ok else "FAIL_CLOSED",
    "phase3_status": "READY_LOCAL_REPLAY" if all_ok else "SAFE_HOLD",
    "claim_ceiling": "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY" if all_ok else "NONE",
    "delta_maglo_claim": "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY" if all_ok else "NONE",
    "global_claim_ceiling": "LAB_ONLY" if all_ok else "LOCKED",
}

Path("risk_outputs").mkdir(parents=True, exist_ok=True)
Path("risk_outputs/risk_substitution_report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(report, indent=2, sort_keys=True))
