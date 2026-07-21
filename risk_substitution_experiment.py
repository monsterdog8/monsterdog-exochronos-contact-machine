#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path

runs = sorted(Path("real_contact_logs").glob("run_*"))
run_dir = runs[-1] if runs else None

hash_verify = {}
hash_verify_path = Path("hash_verify.log")
if hash_verify_path.is_file():
    for line in hash_verify_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        hash_verify[key] = value

required = {
    "hash_verify.log": Path("hash_verify.log").is_file(),
    "FORENSIC_AUDIT.log": Path("FORENSIC_AUDIT.log").is_file(),
    "run_directory_present": run_dir is not None,
    "checks_failed_zero": hash_verify.get("checks_failed") == "0",
    "phase_3_status_ready_local_replay": hash_verify.get("phase_3_status") == "READY_LOCAL_REPLAY",
    "delta_maglo_local_dual_runtime_recompute_only": hash_verify.get("delta_maglo_verdict") == "LOCAL_DUAL_RUNTIME_RECOMPUTE_ONLY",
    "global_ceiling_lab_only": hash_verify.get("global_ceiling") == "LAB_ONLY",
}
all_ok = all(required.values())

report = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mode": "FAIL_CLOSED",
    "run_directory": str(run_dir) if run_dir else None,
    "required_evidence_checks": required,
    "phase_3_status": hash_verify.get("phase_3_status", "SAFE_HOLD"),
    "delta_maglo_rc": hash_verify.get("delta_maglo_rc", "UNKNOWN"),
    "delta_maglo_verdict": hash_verify.get("delta_maglo_verdict", "FAIL_CLOSED"),
    "global_ceiling": hash_verify.get("global_ceiling", "LAB_ONLY"),
    "risk_substitution": {
        "simulated_output_risk": "mitigated_by_observable_artifacts",
        "missing_artifact_risk": "fail_closed_if_detected",
        "external_validation_risk": "not_claimed",
    },
    "verdict": "PASS_LOCAL_ONLY" if all_ok else "FAIL_CLOSED",
    "claim_ceiling": "LAB_ONLY" if all_ok else "NONE",
}

Path("risk_outputs").mkdir(parents=True, exist_ok=True)
Path("risk_outputs/risk_substitution_report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(report, indent=2, sort_keys=True))
