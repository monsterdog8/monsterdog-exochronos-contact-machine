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
  echo "command: git status --short"
  git status --short
} | tee -a "$OUT_DIR/stdout.log"

{
  echo "{"
  echo "\"status\":\"ok\","
  echo "\"run_id\":\"$RUN_ID\","
  echo "\"executed_commands\":[\"date -Iseconds\",\"uname -a\",\"id\",\"ls -la\",\"git status --short\"]"
  echo "}"
} > "$OUT_DIR/result.json"

echo "=== EXECUTION END ===" | tee -a "$OUT_DIR/stdout.log"
