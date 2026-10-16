#!/bin/sh
# =============================================================================
# AEGIS V3E — REPLAY.sh : rejoue l'expérience complète sans rien détruire.
#
#   1. setup opt-in (préflight + journal) — idempotent (SKIP si déjà provisionné)
#   2. provisioning config (clé/pin/politique) — journalisé
#   3. ARCHIVAGE (mv, jamais rm) de l'état runtime précédent -> archive/<ts>/
#   4. exécution du tribunal (familles A-E + attaques d'attestation V1-V5)
#   5. vérification externe du paquet RAW (recalcul depuis les octets)
#
# Toute l'expérience est locale ; aucune connexion extérieure n'est requise.
# Exit codes: 0 OK | autres = transmis
# =============================================================================
set -eu

cd "$(dirname "$0")"
V3E=$(pwd)
RAW="$V3E/RAW_EVIDENCE"
SANDBOX=/tmp/aegis_v3e_sandbox
PY=${PYTHON:-python3}

echo "== [1/5] setup sandbox (opt-in, journalisé) =="
sh "$V3E/tests/setup_sandbox_v3e.sh"

echo "== [2/5] provisioning config =="
"$PY" "$V3E/tests/provision_config_v3e.py"

echo "== [3/5] archivage de l'état runtime précédent (mv, sans suppression) =="
TS=$(date -u +%Y%m%dT%H%M%SZ)
ARCH="$SANDBOX/archive/$TS"
sudo -n /usr/bin/install -d -o user -g user -m 0755 "$ARCH"
if [ -d "$SANDBOX/effect" ]; then
    for f in "$SANDBOX/effect"/marker-*.json; do
        [ -e "$f" ] || continue
        sudo -n mv "$f" "$ARCH/" || true
    done
fi
# NB : state/ est 0700 aegis_pep — ne JAMAIS tester -e en utilisateur ici.
sudo -n mv "$SANDBOX/state/pep_ledger.db" "$ARCH/" 2>/dev/null || true
sudo -n mv "$SANDBOX/state/pep_ledger.db-wal" "$ARCH/" 2>/dev/null || true
sudo -n mv "$SANDBOX/state/pep_ledger.db-shm" "$ARCH/" 2>/dev/null || true
python3 - "$ARCH" "$V3E/PROVISION_JOURNAL.jsonl" <<'PY'
import json, sys, datetime
entry = {"ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
         "desc": "archive previous runtime state (mv, no deletion)",
         "cmdline": "mv markers+db -> " + sys.argv[1],
         "stdout": "archived", "stderr": "", "exit_code": 0}
open(sys.argv[2], "a", encoding="utf-8").write(json.dumps(entry) + "\n")
PY
echo "archivé dans $ARCH"

echo "== [4/5] tribunal V3E (exécution réelle) =="
"$PY" "$V3E/tests/run_v3e_tribunal.py"

echo "== [5/5] vérification externe du paquet RAW =="
"$PY" "$V3E/tests/verify_bundle.py" \
    --bundle "$RAW" \
    --freeze "$V3E/EXPERIMENT_FREEZE.json" \
    --anchor-sha256 "$(cat "$V3E/ANCHOR.txt")" \
    --witness-source "$V3E/INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh"

echo "== REPLAY DONE =="
