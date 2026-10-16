#!/bin/sh
# witness_v3e.sh — AEGIS V3E INDEPENDENT WITNESS (INDEPENDENT_WITNESS_SOURCE)
#
# Minimal independent effect witness. POSIX sh + coreutils ONLY (sha256sum,
# wc, find, sort, date, id, stat). It shares NO code and NO language with
# pep_v3e_effect.py or aegis_v3d/tests/effect_witness.py (verifiable design
# separation; author-instance separation is NOT proven and is reported as such).
#
# Usage: witness_v3e.sh <EFFECT_DIR> <ASSERTION_FILE> [RUN_ID]
#
# ASSERTION_FILE format (TSV, '#' comments allowed):
#   <sha256>  <size_bytes>  <file_name>
#
# Behavior:
#   - lists marker-*.json regular files of EFFECT_DIR (top level, no symlink follow)
#   - recomputes bytes/length/sha256 of each file
#   - compares against the input assertion (name, sha256, size)
#   - prints a raw report (stdout) including effective uid, its own source
#     hash and its run id
#   - WITNESS_VERDICT=VALID only if every assertion matches AND no extra file
#
# Exit codes: 0 VALID | 1 INVALID | 2 usage | 3 unavailable
#
# The witness CONFIRMS NOTHING by default: absence/alteration -> INVALID.

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <EFFECT_DIR> <ASSERTION_FILE> [RUN_ID]" >&2
    exit 2
fi

EFFECT_DIR=$1
ASSERTION_FILE=$2
RUN_ID=${3:-w3e-$(date -u +%Y%m%dT%H%M%SZ)-$$}

if [ ! -d "$EFFECT_DIR" ]; then
    echo "WITNESS_REPORT v3e/1"
    echo "run_id=$RUN_ID"
    echo "WITNESS_VERDICT=UNAVAILABLE"
    echo "reason=effect_dir_missing"
    exit 3
fi
if [ ! -f "$ASSERTION_FILE" ]; then
    echo "WITNESS_REPORT v3e/1"
    echo "run_id=$RUN_ID"
    echo "WITNESS_VERDICT=UNAVAILABLE"
    echo "reason=assertion_file_missing"
    exit 3
fi

SELF_PATH=$0
case "$SELF_PATH" in
    /*) ;;
    *) SELF_PATH=$(pwd)/$SELF_PATH ;;
esac
SELF_HASH=$(sha256sum "$SELF_PATH" | cut -d" " -f1)
EUID_NOW=$(id -u)
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "WITNESS_REPORT v3e/1"
echo "run_id=$RUN_ID"
echo "euid=$EUID_NOW"
echo "witness_source_sha256=$SELF_HASH"
echo "effect_dir=$EFFECT_DIR"
echo "assertion_file=$ASSERTION_FILE"
echo "started_utc=$STARTED"

INVALID=0
SCANNED=0
ASSERTED=0

# --- scan actual files (regular files only; symlinks/refuses counted as EXTRA) ---
SCAN_LIST=$(mktemp)
ASSERT_USED=$(mktemp)
find "$EFFECT_DIR" -maxdepth 1 -name 'marker-*.json' | sort > "$SCAN_LIST"

while IFS= read -r path; do
    [ -n "$path" ] || continue
    name=$(basename "$path")
    SCANNED=$((SCANNED + 1))
    if [ -L "$path" ]; then
        echo "EXTRA name=$name reason=symlink_refused"
        INVALID=1
        continue
    fi
    if [ ! -f "$path" ]; then
        echo "EXTRA name=$name reason=not_regular_file"
        INVALID=1
        continue
    fi
    got_sha=$(sha256sum "$path" | cut -d" " -f1)
    got_size=$(wc -c < "$path" | tr -d " ")
    # find the assertion for this name
    exp_sha=""
    exp_size=""
    while IFS="	" read -r a_sha a_size a_name; do
        case "$a_sha" in \#*|"") continue ;; esac
        if [ "$a_name" = "$name" ]; then
            exp_sha=$a_sha
            exp_size=$a_size
        fi
    done < "$ASSERTION_FILE"
    if [ -z "$exp_sha" ]; then
        echo "FILE name=$name sha256=$got_sha size=$got_size verdict=EXTRA"
        INVALID=1
        continue
    fi
    echo "$name" >> "$ASSERT_USED"
    if [ "$got_sha" = "$exp_sha" ] && [ "$got_size" = "$exp_size" ]; then
        echo "FILE name=$name sha256=$got_sha size=$got_size expect_sha256=$exp_sha expect_size=$exp_size verdict=OK"
    else
        echo "FILE name=$name sha256=$got_sha size=$got_size expect_sha256=$exp_sha expect_size=$exp_size verdict=MISMATCH"
        INVALID=1
    fi
done < "$SCAN_LIST"

# --- assertions with no matching file ---
while IFS="	" read -r a_sha a_size a_name; do
    case "$a_sha" in \#*|"") continue ;; esac
    [ -n "$a_name" ] || continue
    ASSERTED=$((ASSERTED + 1))
    if [ ! -f "$ASSERT_USED" ] || ! grep -qx "$a_name" "$ASSERT_USED"; then
        if [ ! -f "$EFFECT_DIR/$a_name" ]; then
            echo "MISSING name=$a_name expect_sha256=$a_sha expect_size=$a_size"
            INVALID=1
        fi
    fi
done < "$ASSERTION_FILE"

rm -f "$SCAN_LIST" "$ASSERT_USED"

echo "scanned=$SCANNED asserted=$ASSERTED"
echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$INVALID" -eq 0 ] && [ "$SCANNED" -eq "$ASSERTED" ]; then
    echo "WITNESS_VERDICT=VALID"
    exit 0
else
    echo "WITNESS_VERDICT=INVALID"
    exit 1
fi
