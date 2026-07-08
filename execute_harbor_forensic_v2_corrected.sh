#!/bin/bash
set -euo pipefail

RUN_ID=$(date +%s)
OUT_DIR="real_contact_logs/run_$RUN_ID"

mkdir -p "$OUT_DIR"

echo "=== EXECUTION START ===" | tee "$OUT_DIR/stdout.log"

{
  echo "{"
  echo "\"timestamp\": \"$(date -Iseconds)\","
  echo "\"hostname\": \"$(hostname)\","
  echo "\"user\": \"$(whoami)\","
  echo "\"run_id\": \"$RUN_ID\""
  echo "}"
} > "$OUT_DIR/environment.json"

echo "Simulated execution..." | tee -a "$OUT_DIR/stdout.log"

echo "{\"status\":\"ok\",\"run_id\":\"$RUN_ID\"}" > "$OUT_DIR/result.json"

echo "=== EXECUTION END ===" | tee -a "$OUT_DIR/stdout.log"
