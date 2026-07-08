#!/bin/bash
set -euo pipefail

RUN_ID=$(date +%s%N)
OUT_DIR="real_contact_logs/run_$RUN_ID"

mkdir -p "$OUT_DIR"

echo "=== EXECUTION START ===" | tee "$OUT_DIR/stdout.log"

{
  echo "{"
  echo "\"timestamp\": \"$(date -Iseconds)\","
  echo "\"hostname\": \"$(hostname)\","
  echo "\"user\": \"$(whoami)\","
  echo "\"cwd\": \"$(pwd)\","
  echo "\"run_id\": \"$RUN_ID\""
  echo "}"
} > "$OUT_DIR/environment.json"

{
  echo "command: date -Iseconds"
  date -Iseconds
  echo "command: uname -a"
  uname -a
  echo "command: id"
  id
  echo "command: ls -la"
  ls -la
} | tee -a "$OUT_DIR/stdout.log"

echo "command: curl -s https://api.github.com" | tee -a "$OUT_DIR/stdout.log"
curl -s https://api.github.com > "$OUT_DIR/network_output.json"
wc -c < "$OUT_DIR/network_output.json" | awk '{print "network_output_bytes: " $1}' | tee -a "$OUT_DIR/stdout.log"

echo "command: python3 - (heredoc computation workload)" | tee -a "$OUT_DIR/stdout.log"
OUT_DIR="$OUT_DIR" python3 - <<'PY' > "$OUT_DIR/computation_output.json"
import hashlib
import json
import math
import os
from pathlib import Path

out_dir = Path(os.environ["OUT_DIR"])
network_bytes = (out_dir / "network_output.json").read_bytes()

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = int(math.sqrt(n))
    for i in range(3, r + 1, 2):
        if n % i == 0:
            return False
    return True

limit = 50000
prime_count = sum(1 for n in range(limit + 1) if is_prime(n))
sha = hashlib.sha256(network_bytes).hexdigest()

payload = {
    "network_bytes": len(network_bytes),
    "network_sha256": sha,
    "prime_count": prime_count,
    "prime_limit": limit,
}
print(json.dumps(payload, sort_keys=True))
PY
cat "$OUT_DIR/computation_output.json" | tee -a "$OUT_DIR/stdout.log"

{
  printf '{\n'
  printf '"status":"ok",\n'
  printf '"run_id":"%s",\n' "$RUN_ID"
  printf '"network_output_sha256":"%s",\n' "$(sha256sum "$OUT_DIR/network_output.json" | awk '{print $1}')"
  printf '"computation_output_sha256":"%s",\n' "$(sha256sum "$OUT_DIR/computation_output.json" | awk '{print $1}')"
  printf '"executed_commands":["date -Iseconds","uname -a","id","ls -la","curl -s https://api.github.com","python3 -"]\n'
  printf '}\n'
} > "$OUT_DIR/result.json"

echo "=== EXECUTION END ===" | tee -a "$OUT_DIR/stdout.log"
