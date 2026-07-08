#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

TIMESTAMP="${1:-$(date -u +%Y%m%d_%H%M%S)}"
RUN_DIR="real_contact_logs/run_${TIMESTAMP}"

mkdir -p "$RUN_DIR" audit_outputs replay_outputs risk_outputs

{
  echo "# EXOCHRONOS Phase 3 Local Execution Trace"
  echo "started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host_uname=$(uname -a)"
  echo "current_user=$(id)"
  echo "working_directory=$(pwd)"
  echo "git_head=$(git rev-parse HEAD)"
  echo "git_branch=$(git branch --show-current)"
  echo "--- git status --short ---"
  git status --short
  echo "--- directory listing ---"
  ls -la
  echo "--- python version ---"
  python3 --version
} > "$RUN_DIR/stdout.log"

python3 - <<'PY' > "$RUN_DIR/environment.json"
import json
import os
from datetime import datetime, timezone

keys = [
    "SHELL", "USER", "HOME", "PWD", "PATH", "LANG", "TZ", "PYTHONPATH"
]
env = {k: os.environ.get(k) for k in keys}
out = {
    "captured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "selected_environment": env,
    "environment_key_count": len(os.environ),
}
print(json.dumps(out, indent=2, sort_keys=True))
PY

python3 - <<'PY' > "$RUN_DIR/result.json"
import json
import platform
import subprocess
from datetime import datetime, timezone

head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()

out = {
    "phase": 3,
    "mode": "FAIL_CLOSED",
    "claim_ceiling": "STRUCTURAL_LOCAL_ONLY",
    "observables_only": True,
    "local_only_until_replay": True,
    "executed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "host": {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    },
    "repository": {
        "branch": branch,
        "head": head,
    },
    "status": "OBSERVED_LOCAL_EXECUTION",
}
print(json.dumps(out, indent=2, sort_keys=True))
PY

python3 - <<PY > "$RUN_DIR/execution_manifest.json"
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

run_dir = Path("$RUN_DIR")
entries = []
for name in ["stdout.log", "environment.json", "result.json"]:
    p = run_dir / name
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    entries.append({"file": name, "sha256": digest, "size_bytes": p.stat().st_size})

manifest = {
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run_directory": str(run_dir),
    "artifact_count": len(entries) + 1,
    "artifacts": entries,
    "mode": "FAIL_CLOSED",
}
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

echo "$RUN_DIR"
