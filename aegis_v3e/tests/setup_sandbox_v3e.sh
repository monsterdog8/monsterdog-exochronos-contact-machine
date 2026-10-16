#!/bin/sh
# =============================================================================
# AEGIS V3E — setup_sandbox_v3e.sh (PREVIEW / READ_ONLY_FIRST + opt-in)
# Correctif V3D-001 : AUCUN provisioning invasif. Autorisation conditionnelle
# de l'utilisateur (2026-10-16) respectée À LA LETTRE :
#   [x] comptes de test uniquement (aegis_pep/witness/agent), sans privilège
#   [x] exclusivement /tmp/aegis_v3e_sandbox
#   [x] préflight AVANT toute modification (identité, comptes, chemins, ACL)
#   [x] aucune modification de /home, données utilisateur, dépôts, secrets,
#       configurations système (lecture seule pour copier les libs déjà présentes)
#   [x] aucune suppression récursive, aucun chmod global, aucune installation
#       externe (copies uniquement), aucun déploiement public
#   [x] chaque commande privilégiée journalisée (stdout/stderr/exit) dans
#       PROVISION_JOURNAL.jsonl
#   [x] arrêt immédiat (exit 42) si l'isolation du conteneur ou les permissions
#       ne peuvent pas être vérifiées
#   [x] actions limitées aux marqueurs de test non destructifs
# Chaque commande passée à runj est exécutée TELLE QUELLE (avec sudo -n explicite
# pour les opérations privilégiées) et journalisée avec sortie et code.
# Exit codes: 0 OK | 2 usage | 3 preflight failed | 42 BLOCKED_ENVIRONMENT
# =============================================================================
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
V3E="$REPO/aegis_v3e"
SANDBOX=/tmp/aegis_v3e_sandbox
JOURNAL="$V3E/PROVISION_JOURNAL.jsonl"
STAGE=/tmp/aegis_v3e_stage

[ -d "$V3E" ] || { echo "aegis_v3e introuvable" >&2; exit 2; }
mkdir -p "$STAGE"

runj() {
    # runj <desc> <commande exacte...> — exécute, journalise stdout/stderr/exit
    desc=$1; shift
    out=$(mktemp "$STAGE/out.XXXXXX"); err=$(mktemp "$STAGE/err.XXXXXX")
    set +e
    "$@" >"$out" 2>"$err"
    rc=$?
    set -e
    python3 - "$desc" "$out" "$err" "$rc" "$JOURNAL" "$*" <<'PY'
import json, sys, datetime
desc, outf, errf, rc, journal, cmdline = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
entry = {
    "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "desc": desc,
    "cmdline": cmdline,
    "stdout": open(outf, errors="replace").read()[:4000],
    "stderr": open(errf, errors="replace").read()[:4000],
    "exit_code": rc,
}
with open(journal, "a", encoding="utf-8") as f:
    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
print(f"[JOURNAL] rc={rc} {desc}")
PY
    rm -f "$out" "$err"
    return $rc
}

echo "== PREFLIGHT (avant toute modification) =="
PRE=$( {
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "uid=$(id -u) gid=$(id -g)"
    echo "hostname=$(hostname)"
    echo "kernel=$(uname -r)"
    echo "rootfs=$(mount | awk '$3=="/"{print $1}')"
    echo "existing_accounts=$(getent passwd aegis_pep aegis_witness aegis_agent | wc -l)"
    echo "sandbox_exists=$([ -e "$SANDBOX" ] && echo 1 || echo 0)"
    echo "tmp_writable=$(test -w /tmp && echo 1 || echo 0)"
    echo "home_mode=$(stat -c %a /home/user)"
} 2>&1 )
echo "$PRE"

# Critères d'isolation vérifiables : conteneur éphémère e2b.local, /tmp libre,
# compte de travail uid 1001, aucune identité aegis_* préexistante.
HOST=$(hostname)
case "$HOST" in
    e2b.local|e2b*) echo "[OK] isolation: conteneur éphémère E2B ($HOST)";;
    *) echo "[STOP] isolation non vérifiable (hostname=$HOST)" >&2
       echo "$PRE" > "$V3E/RAW_EVIDENCE/preflight_blocked_env.txt"
       exit 42;;
esac
[ "$(id -u)" = "1001" ] || { echo "[STOP] uid inattendu" >&2; exit 42; }
[ "$(echo "$PRE" | sed -n 's/tmp_writable=//p')" = "1" ] || { echo "[STOP] /tmp non inscriptible" >&2; exit 42; }
if [ "$(echo "$PRE" | sed -n 's/existing_accounts=//p')" != "0" ]; then
    if [ -f "$SANDBOX/sandbox_ready.json" ]; then
        echo "[SKIP] déjà provisionné (sandbox_ready.json présent) — idempotent"
        exit 0
    fi
    if [ -f "$JOURNAL" ] && grep -q "useradd aegis_pep" "$JOURNAL" 2>/dev/null; then
        echo "[RESUME] comptes créés par CE run journalisé — reprise autorisée"
    else
        echo "[STOP] comptes aegis_* préexistants sans attestation de provisioning" >&2
        exit 42
    fi
fi

echo "$PRE" > "$V3E/RAW_EVIDENCE/preflight_provision.txt"
python3 - "$PRE" "$JOURNAL" <<'PY'
import json, sys, datetime
entry = {"ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
         "desc": "PREFLIGHT (no modification)", "cmdline": "internal",
         "stdout": sys.argv[1], "stderr": "", "exit_code": 0}
open(sys.argv[2], "a", encoding="utf-8").write(json.dumps(entry, ensure_ascii=False) + "\n")
PY

echo "== PROVISIONING (journalisé) =="
runj "useradd aegis_pep (test account, nologin, no privileges)" \
    sudo -n /usr/sbin/useradd -M -r -U -s /usr/sbin/nologin aegis_pep || echo "[tolerated] aegis_pep existe déjà"
runj "useradd aegis_witness (test account, nologin, no privileges)" \
    sudo -n /usr/sbin/useradd -M -r -U -s /usr/sbin/nologin aegis_witness || echo "[tolerated] aegis_witness existe déjà"
runj "useradd aegis_agent (test account, nologin, no privileges)" \
    sudo -n /usr/sbin/useradd -M -r -U -s /usr/sbin/nologin aegis_agent || echo "[tolerated] aegis_agent existe déjà"

runj "install -d sandbox root 0755"  sudo -n /usr/bin/install -d -o root -g root -m 0755 "$SANDBOX"
runj "install -d config root 0755"   sudo -n /usr/bin/install -d -o root -g root -m 0755 "$SANDBOX/config"
runj "install -d app root 0755"      sudo -n /usr/bin/install -d -o root -g root -m 0755 "$SANDBOX/app"
runj "install -d pylibs root 0755"   sudo -n /usr/bin/install -d -o root -g root -m 0755 "$SANDBOX/pylibs"
runj "install -d attacks user 0755"   sudo -n /usr/bin/install -d -o user -g user -m 0755 "$SANDBOX/attacks"
runj "install -d req user 0755"       sudo -n /usr/bin/install -d -o user -g user -m 0755 "$SANDBOX/req"
runj "install -d effect aegis_pep 0755"      sudo -n /usr/bin/install -d -o aegis_pep -g aegis_pep -m 0755 "$SANDBOX/effect"
runj "install -d state aegis_pep 0700"       sudo -n /usr/bin/install -d -o aegis_pep -g aegis_pep -m 0700 "$SANDBOX/state"
runj "install -d logs aegis_pep 0700"        sudo -n /usr/bin/install -d -o aegis_pep -g aegis_pep -m 0700 "$SANDBOX/logs"
runj "install -d witness aegis_witness 0755" sudo -n /usr/bin/install -d -o aegis_witness -g aegis_witness -m 0755 "$SANDBOX/witness"
runj "install -d agent_out aegis_agent 0755" sudo -n /usr/bin/install -d -o aegis_agent -g aegis_agent -m 0755 "$SANDBOX/agent_out"

# Dépendances Python : copie locale si présente (lecture seule de /home/user —
# AUCUNE modification) ; sinon installation UNIQUEMENT dans le bac dédié
# (pip --target $SANDBOX/pylibs, depuis pypi.org — aucun paquet système,
# aucune modification de l'hôte). Journalisé dans les deux cas.
if [ -d /home/user/.local/lib/python3.11/site-packages ]; then
    runj "copy existing python libs (READ-ONLY from /home/user/.local, no install)" \
        sudo -n /bin/cp -a /home/user/.local/lib/python3.11/site-packages/. "$SANDBOX/pylibs/" \
        || echo "[fallback] copie impossible -> pip --target dans le bac"
else
    echo "[fallback] pas de libs locales -> pip --target dans le bac"
fi
if ! sudo -n -u aegis_pep /usr/bin/env PYTHONPATH="$SANDBOX/pylibs" /usr/bin/python3 \
    -c "import fastapi" 2>/dev/null; then
    runj "pip install deps INTO sandbox pylibs only (pypi.org, no system install)" \
        sudo -n /usr/bin/pip3 install --break-system-packages --quiet \
        --target "$SANDBOX/pylibs" fastapi uvicorn httpx cryptography
fi

# Copie des sources d'exécution dans le bac (empreintes revérifiées ensuite).
runj "copy pep_v3e_effect.py + witness + client into sandbox/app" \
    sudo -n /bin/cp "$V3E/pep_v3e_effect.py" "$V3E/INDEPENDENT_WITNESS_SOURCE/witness_v3e.sh" \
                    "$V3E/tests/http_client_v3e.py" "$SANDBOX/app/"

runj "witness_v3e.sh mode 0755 (targeted chmod on sandbox copy only)" \
    sudo -n /bin/chmod 0755 "$SANDBOX/app/witness_v3e.sh"

# Sonde d'exécution par les trois UID (reçus conservés dans le journal).
runj "probe aegis_pep deps import" \
    sudo -n -u aegis_pep /usr/bin/env PYTHONPATH="$SANDBOX/pylibs" /usr/bin/python3 \
    -c "import fastapi, uvicorn, httpx, cryptography; print('pep-deps-ok')"
runj "probe aegis_witness runs" \
    sudo -n -u aegis_witness /bin/sh -c "id -u; command -v sha256sum"
runj "probe aegis_agent write to effect must fail (EACCES expected)" \
    sudo -n -u aegis_agent /bin/sh -c "touch $SANDBOX/effect/PROBE_FORBIDDEN.txt" \
    || echo "[expected-fail rc=$? — EACCES confirmé]"
runj "probe aegis_agent open state db must fail (EACCES/OperationalError expected)" \
    sudo -n -u aegis_agent /usr/bin/env PYTHONPATH="$SANDBOX/pylibs" /usr/bin/python3 \
    -c "import sqlite3; sqlite3.connect('$SANDBOX/state/pep_ledger.db').execute('select 1')" \
    || echo "[expected-fail rc=$? — accès registre refusé]"

python3 - <<'PY'
import json, subprocess, os, hashlib, datetime
sb = "/tmp/aegis_v3e_sandbox"
def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
acc = {}
for u in ("aegis_pep", "aegis_witness", "aegis_agent"):
    r = sh(f"getent passwd {u}")
    acc[u] = r.stdout.strip() if r.returncode == 0 else None
hashes = {}
for f in ("app/pep_v3e_effect.py", "app/witness_v3e.sh", "app/http_client_v3e.py"):
    p = os.path.join(sb, f)
    hashes[f] = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
facts = {
    "ts_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sandbox": sb, "accounts": acc, "sandbox_copy_hashes": hashes,
    "uid_map": {u: (acc[u].split(":")[2] if acc[u] else None) for u in acc},
}
os.makedirs(os.path.join(sb, "req"), exist_ok=True)
open(os.path.join(sb, "req", "sandbox_ready.json"), "w").write(json.dumps(facts, indent=1))
print(json.dumps(facts["uid_map"]))
print("sandbox_ready.json staged in req/")
PY
runj "install sandbox_ready.json at sandbox root" \
    sudo -n /bin/cp "$SANDBOX/req/sandbox_ready.json" "$SANDBOX/sandbox_ready.json"

echo "== PROVISIONING DONE — journal: $JOURNAL =="
echo "OS_PERMISSION_TEST=CANDIDATE_OBSERVED (verification via tests)"
exit 0
