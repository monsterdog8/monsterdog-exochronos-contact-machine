#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path

runs = sorted(Path("real_contact_logs").glob("run_*"))
run_dir = runs[-1] if runs else None

required = {
    "hash_verify.log": Path("hash_verify.log").is_file(),
    "FORENSIC_AUDIT.log": Path("FORENSIC_AUDIT.log").is_file(),
    "run_directory_present": run_dir is not None,
}
all_ok = all(required.values())

report = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mode": "FAIL_CLOSED",
    "run_directory": str(run_dir) if run_dir else None,
    "required_evidence_checks": required,
    "risk_substitution": {
        "simulated_output_risk": "mitigated_by_observable_artifacts",
        "missing_artifact_risk": "fail_closed_if_detected",
        "external_validation_risk": "not_claimed",
    },
    "verdict": "PASS_LOCAL_ONLY" if all_ok else "FAIL_CLOSED",
    "claim_ceiling": "STRUCTURAL_LOCAL_ONLY" if all_ok else "NONE",
}

Path("risk_outputs").mkdir(parents=True, exist_ok=True)
Path("risk_outputs/risk_substitution_report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(report, indent=2, sort_keys=True))
