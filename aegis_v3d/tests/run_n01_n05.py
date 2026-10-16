#!/usr/bin/env python3
"""Reproduction des 5 contre-épreuves NEMESIS N01–N05.

Partie A — sur le PEP V3C PRÉSERVÉ (chargé par chemin, sans rien modifier) :
confirmation des constats du tribunal NEMESIS.
Partie B — sur le PEP V3D dans le bac OS à UID séparés : qualification des
correctifs (FIXED / SCOPE_MOVED_TO_OS / LAYERED).

Aucun PASS sans exécution. CLAIM <= EVIDENCE.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
AEGIS_V3D_DIR = HERE.parent
REPO = AEGIS_V3D_DIR.parent
V3C_DIR = REPO / "aegis_v3c"
RESULTS = AEGIS_V3D_DIR / "results"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(AEGIS_V3D_DIR))

import harness_v3d as H  # noqa: E402

RESULTS.mkdir(exist_ok=True)

N_REPORT: List[Dict[str, Any]] = []


def record(nid: str, target: str, title: str, nemesis_finding: str,
           observed: Dict[str, Any], verdict: str) -> None:
    N_REPORT.append({
        "id": nid,
        "target": target,
        "title": title,
        "nemesis_finding": nemesis_finding,
        "observed": observed,
        "verdict": verdict,
    })
    print(f"[{verdict:24s}] {nid} ({target}) {title}")
    print(f"    observed: {json.dumps(observed, ensure_ascii=False)[:420]}")


# ---------------------------------------------------------------------------
# Chargement isolé du module V3C historique (aucune écriture rétroactive)
# ---------------------------------------------------------------------------

def load_v3c():
    spec = importlib.util.spec_from_file_location(
        "pep_v3c_pinned_historical", V3C_DIR / "pep_v3c_pinned.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pep_v3c_pinned_historical"] = mod  # requis par @dataclass
    spec.loader.exec_module(mod)
    return mod


def v3c_workspace(root: Path, v3c, priv, pub_raw):
    root.mkdir(parents=True, exist_ok=True)
    (root / "pep_public.key").write_bytes(pub_raw)
    fp = H.fingerprint(pub_raw)
    (root / "trust_root.pin").write_text(fp + "\n", encoding="utf-8")
    policy = {
        "policy_version": "v3c.1.0",
        "audience": "monsterdog.pep.local",
        "trust_root_fingerprint": fp,
        "allowed_issuers": ["monsterdog.core.v3c"],
        "allowlist": [
            {"subject": "agent-alpha", "action": "report.read", "resource": "reports/*"},
            {"subject": "agent-alpha", "action": "email.send", "resource": "outbox/digest"},
        ],
        "max_ttl_seconds": 300,
        "max_issued_at_skew_seconds": 60,
    }
    (root / "pep_policy_v3c.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")
    return policy


# ===========================================================================
# PARTIE A — V3C préservé
# ===========================================================================

def part_a_v3c() -> None:
    from fastapi.testclient import TestClient

    v3c = load_v3c()
    priv = H.load_signer()
    pub_raw = H.legit_pub_raw()
    ws = RESULTS / "n_v3c_workspace"
    if ws.exists():
        shutil.rmtree(ws)
    v3c_workspace(ws, v3c, priv, pub_raw)

    app = v3c.build_app(
        str(ws / "pep_policy_v3c.json"), str(ws / "pep_public.key"),
        str(ws / "trust_root.pin"), str(ws / "pep_ledger.db"),
    )
    client = TestClient(app)
    now = time.time()

    def req():
        return H.make_request("agent-alpha", "report.read", "reports/q3")

    # --- N01 : champ system_eval supplémentaire ---------------------
    nonce = "N01-" + str(int(now))
    permit = H.forge_permit(
        permit_id="P-N01", nonce=nonce, orig_request=req(),
        issued_at=now - 2, expires_at=now + 120,
        issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
        policy_version="v3c.1.0",
    )
    payload = {"original_request": req(), "permit": permit,
               "system_eval": "__import__('os').system('id')"}
    r = client.post("/v1/execute", json=payload)
    record(
        "N01", "V3C",
        "Champ JSON externe system_eval sur requête légitime",
        "wrapper permissif : HTTP 200 silencieux",
        {"status_code": r.status_code, "body": r.json()},
        "REPRODUCED" if r.status_code == 200 else "NOT_REPRODUCED",
    )

    # --- N02 : même permit_id, nonces distincts ---------------------
    r1req = req()
    p_a = H.forge_permit(permit_id="P-SHARED", nonce="N02-A-" + str(int(now)),
                         orig_request=r1req, issued_at=now - 2, expires_at=now + 120,
                         issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
                         policy_version="v3c.1.0")
    p_b = H.forge_permit(permit_id="P-SHARED", nonce="N02-B-" + str(int(now)),
                         orig_request=r1req, issued_at=now - 2, expires_at=now + 120,
                         issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
                         policy_version="v3c.1.0")
    r1 = client.post("/v1/execute", json={"original_request": r1req, "permit": p_a})
    r2 = client.post("/v1/execute", json={"original_request": r1req, "permit": p_b})
    record(
        "N02", "V3C",
        "Deux permis, même permit_id, nonces distincts",
        "200 puis 200 : unicité nonce seulement, pas d'idempotence métier",
        {"first": r1.status_code, "second": r2.status_code},
        "REPRODUCED" if (r1.status_code, r2.status_code) == (200, 200) else "NOT_REPRODUCED",
    )

    # --- N03 : révocation de politique non effective ----------------
    r3req = req()
    p_c = H.forge_permit(permit_id="P-N03", nonce="N03-" + str(int(now)),
                         orig_request=r3req, issued_at=now - 2, expires_at=now + 120,
                         issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
                         policy_version="v3c.1.0")
    before = client.post("/v1/execute", json={"original_request": r3req, "permit": p_c})
    # révocation administrative : on retire report.read de la politique
    pol_path = ws / "pep_policy_v3c.json"
    pol = json.loads(pol_path.read_text())
    pol["allowlist"] = [{"subject": "agent-alpha", "action": "email.send", "resource": "outbox/digest"}]
    pol_path.write_text(json.dumps(pol, indent=2))
    r3req2 = req()
    p_d = H.forge_permit(permit_id="P-N03B", nonce="N03B-" + str(int(now)),
                         orig_request=r3req2, issued_at=now - 2, expires_at=now + 120,
                         issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
                         policy_version="v3c.1.0")
    after = client.post("/v1/execute", json={"original_request": r3req2, "permit": p_d})
    record(
        "N03", "V3C",
        "Révocation de politique après démarrage",
        "autorisation chargée non révoquée : HTTP 200 après modification disque",
        {"before_change": before.status_code, "after_revocation": after.status_code},
        "REPRODUCED" if (before.status_code, after.status_code) == (200, 200) else "NOT_REPRODUCED",
    )

    # --- N04 : remplacement conjoint clé + pin + politique ----------
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    evil_priv = ed25519.Ed25519PrivateKey.generate()
    evil_pub = evil_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ws_evil = RESULTS / "n_v3c_evil_config"
    if ws_evil.exists():
        shutil.rmtree(ws_evil)
    v3c_workspace(ws_evil, v3c, evil_priv, evil_pub)  # clé+pin+politique de l'attaquant
    app_evil = v3c.build_app(
        str(ws_evil / "pep_policy_v3c.json"), str(ws_evil / "pep_public.key"),
        str(ws_evil / "trust_root.pin"), str(ws_evil / "pep_ledger.db"),
    )
    client_evil = TestClient(app_evil)
    r4req = req()
    # permis signé par la clé substituée, issuer adapté à la politique substituée
    p_e = H.forge_permit(
        evil_priv,
        permit_id="P-N04", nonce="N04-" + str(int(now)),
        orig_request=r4req, issued_at=now - 2, expires_at=now + 120,
        issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
        policy_version="v3c.1.0",
    )
    r4 = client_evil.post("/v1/execute", json={"original_request": r4req, "permit": p_e})
    record(
        "N04", "V3C",
        "Remplacement conjoint clé publique + pin + politique",
        "racine réinstallée par l'attaquant : HTTP 200 (3 fichiers mutables != racine)",
        {"status_code": r4.status_code, "body": r4.json()},
        "REPRODUCED" if r4.status_code == 200 else "NOT_REPRODUCED",
    )

    # --- N05 : rollback du registre SQLite --------------------------
    r5req = req()
    p_f = H.forge_permit(permit_id="P-N05", nonce="N05-" + str(int(now)),
                         orig_request=r5req, issued_at=now - 2, expires_at=now + 120,
                         issuer="monsterdog.core.v3c", audience="monsterdog.pep.local",
                         policy_version="v3c.1.0")
    first = client.post("/v1/execute", json={"original_request": r5req, "permit": p_f})
    import sqlite3
    conn = sqlite3.connect(ws / "pep_ledger.db")
    conn.execute("DELETE FROM consumed_permits")
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM effect_journal")
    conn.commit()
    conn.close()
    replay = client.post("/v1/execute", json={"original_request": r5req, "permit": p_f})
    record(
        "N05", "V3C",
        "Rollback simulé du registre (DELETE des 3 tables)",
        "même permis réaccepté : HTTP 200 (pas de témoin monotone)",
        {"first": first.status_code, "replay_after_rollback": replay.status_code},
        "REPRODUCED" if (first.status_code, replay.status_code) == (200, 200) else "NOT_REPRODUCED",
    )


# ===========================================================================
# PARTIE B — V3D dans le bac OS
# ===========================================================================

def part_b_v3d() -> None:
    H.ensure_sandbox_dirs()
    H.reset_runtime_state()
    now = time.time()
    server = H.ServerHandle(name="S_N")
    server.start()

    def req_marker(pid: str):
        return H.make_request("agent-alpha", "marker.create", f"effect/marker-{pid}.json")

    def req_read():
        return H.make_request("agent-alpha", "report.read", "reports/q3")

    # --- N01 : system_eval => enveloppe fermée ----------------------
    r1req = req_read()
    p1 = H.forge_permit(permit_id="P-VN01", nonce="VN01-" + str(int(now)),
                        orig_request=r1req, issued_at=now - 2, expires_at=now + 120)
    payload = {"original_request": r1req, "permit": p1,
               "system_eval": "__import__('os').system('id')"}
    v = H.agent_post(server.base_url, payload, "n01")
    record(
        "N01", "V3D",
        "Champ JSON externe system_eval (extra=forbid)",
        "V3C acceptait en silence ; V3D doit refuser",
        v,
        "FIXED" if v.get("status_code") == 422 else "NOT_FIXED",
    )

    # --- N02 : permit_id UNIQUE ------------------------------------
    r2req = req_read()
    p2a = H.forge_permit(permit_id="P-VN02", nonce="VN02-A-" + str(int(now)),
                         orig_request=r2req, issued_at=now - 2, expires_at=now + 120)
    p2b = H.forge_permit(permit_id="P-VN02", nonce="VN02-B-" + str(int(now)),
                         orig_request=r2req, issued_at=now - 2, expires_at=now + 120)
    v2a = H.agent_post(server.base_url, {"original_request": r2req, "permit": p2a}, "n02a")
    v2b = H.agent_post(server.base_url, {"original_request": r2req, "permit": p2b}, "n02b")
    code2 = (v2b.get("body") or {}).get("detail", {})
    code2 = code2.get("code") if isinstance(code2, dict) else code2
    record(
        "N02", "V3D",
        "Même permit_id, nonces distincts",
        "V3C donnait 200/200 ; V3D doit refuser le second (idempotence métier)",
        {"first": v2a.get("status_code"), "second": v2b.get("status_code"), "second_code": code2},
        "FIXED" if (v2a.get("status_code") == 200 and v2b.get("status_code") == 403
                    and code2 == "PERMIT_ID_REUSED") else "NOT_FIXED",
    )

    # --- N03 : révocation à chaud effective à la requête suivante ---
    r3req = req_read()
    p3 = H.forge_permit(permit_id="P-VN03", nonce="VN03-" + str(int(now)),
                        orig_request=r3req, issued_at=now - 2, expires_at=now + 120)
    before = H.agent_post(server.base_url, {"original_request": r3req, "permit": p3}, "n03a")
    pol_path = H.CONFIG / "pep_policy_v3d.json"
    pol = json.loads(pol_path.read_text())
    removed = [r for r in pol["allowlist"] if r["action"] == "report.read"]
    pol["allowlist"] = [r for r in pol["allowlist"] if r["action"] != "report.read"]
    stage = RESULTS / "policy_stage.json"
    stage.write_text(json.dumps(pol, indent=2) + "\n")
    subprocess.run(["sudo", "cp", str(stage), str(pol_path)], check=True)
    r3req2 = req_read()
    p3b = H.forge_permit(permit_id="P-VN03B", nonce="VN03B-" + str(int(now)),
                         orig_request=r3req2, issued_at=now - 2, expires_at=now + 120)
    after = H.agent_post(server.base_url, {"original_request": r3req2, "permit": p3b}, "n03b")
    code3 = (after.get("body") or {}).get("detail", {})
    code3 = code3.get("code") if isinstance(code3, dict) else code3
    # restauration de la politique
    pol["allowlist"].extend(removed)
    stage.write_text(json.dumps(pol, indent=2) + "\n")
    subprocess.run(["sudo", "cp", str(stage), str(pol_path)], check=True)
    record(
        "N03", "V3D",
        "Révocation administrative de politique",
        "V3C ignorait la modification ; contrat V3D : effective à la requête suivante",
        {"before": before.get("status_code"), "after_revocation": after.get("status_code"),
         "after_code": code3, "policy_restored": True},
        "FIXED" if (before.get("status_code") == 200 and after.get("status_code") == 403
                    and code3 == "ACTION_FORBIDDEN") else "NOT_FIXED",
    )

    # --- N04 : remplacement conjoint par l'agent => OS EACCES --------
    evil = H.agent_exec(
        "from cryptography.hazmat.primitives.asymmetric import ed25519\n"
        "import os\n"
        "p='/tmp/aegis_v3d_sandbox/config/pep_public.key'\n"
        "try:\n"
        "    open(p,'wb').write(b'A'*32)\n"
        "    print('WRITE_OK')\n"
        "except PermissionError as e:\n"
        "    print('EACCES')\n"
    )
    evil_pin = H.agent_exec(
        "p='/tmp/aegis_v3d_sandbox/config/trust_root.pin'\n"
        "try:\n"
        "    open(p,'w').write('deadbeef')\n"
        "    print('WRITE_OK')\n"
        "except PermissionError:\n"
        "    print('EACCES')\n"
    )
    evil_pol = H.agent_exec(
        "p='/tmp/aegis_v3d_sandbox/config/pep_policy_v3d.json'\n"
        "try:\n"
        "    open(p,'w').write('{}')\n"
        "    print('WRITE_OK')\n"
        "except PermissionError:\n"
        "    print('EACCES')\n"
    )
    # contrôle : la config est intacte et le PEP sert toujours la même racine
    health = server.health()
    record(
        "N04", "V3D",
        "Remplacement conjoint clé+pin+politique tenté par l'agent non fiable",
        "V3C : 200 (fichiers mutables) ; V3D : refus OS sur les 3 fichiers",
        {"write_key": evil, "write_pin": evil_pin, "write_policy": evil_pol,
         "pep_health_after": health},
        "SCOPE_MOVED_TO_OS" if (
            evil["stdout"] == "EACCES" and evil_pin["stdout"] == "EACCES"
            and evil_pol["stdout"] == "EACCES" and health.get("trust_root") == "OK"
        ) else "NOT_FIXED",
    )

    # --- N05 : rollback registre ------------------------------------
    r5req = req_marker("P-VN05")
    p5 = H.forge_permit(permit_id="P-VN05", nonce="VN05-" + str(int(now)),
                        orig_request=r5req, issued_at=now - 2, expires_at=now + 120)
    first = H.agent_post(server.base_url, {"original_request": r5req, "permit": p5}, "n05a")

    # (a) tentative de rollback par l'agent => OS EACCES
    agent_rb = H.agent_exec(
        "import sqlite3\n"
        "try:\n"
        "    conn=sqlite3.connect('/tmp/aegis_v3d_sandbox/state/pep_ledger.db')\n"
        "    conn.execute('DELETE FROM consumed_permits')\n"
        "    conn.commit()\n"
        "    print('DELETE_OK')\n"
        "except Exception as e:\n"
        "    print(type(e).__name__)\n"
    )
    agent_list = H.agent_exec(
        "import os\n"
        "try:\n"
        "    os.listdir('/tmp/aegis_v3d_sandbox/state')\n"
        "    print('LIST_OK')\n"
        "except PermissionError:\n"
        "    print('EACCES')\n"
    )
    replay_blocked = H.agent_post(server.base_url, {"original_request": r5req, "permit": p5}, "n05b")
    code_rb = (replay_blocked.get("body") or {}).get("detail", {})
    code_rb = code_rb.get("code") if isinstance(code_rb, dict) else code_rb

    # (b) rollback PRIVILÉGIÉ (propriétaire du registre) : démonstration
    floor = H.chain_head()
    nonce5 = "VN05-" + str(int(now))
    rb_code = (
        "import sqlite3, sys\n"
        "conn = sqlite3.connect('/tmp/aegis_v3d_sandbox/state/pep_ledger.db')\n"
        "n = sys.argv[1]\n"
        "for t in ('consumed_permits', 'events', 'effect_journal'):\n"
        "    conn.execute(f'DELETE FROM {t} WHERE nonce=?', (n,))\n"
        "conn.commit()\n"
    )
    subprocess.run(
        ["sudo", "-u", "aegis_pep", H.VENV_PY, "-c", rb_code, nonce5],
        check=True,
    )
    after_head = H.chain_head()
    replay_priv = H.agent_post(server.base_url, {"original_request": r5req, "permit": p5}, "n05c")
    code_priv = (replay_priv.get("body") or {}).get("detail", {})
    code_priv = code_priv.get("code") if isinstance(code_priv, dict) else code_priv
    # le marqueur FS survit au rollback DB : O_EXCL = second étage anti-rejeu
    record(
        "N05", "V3D",
        "Rollback du registre : agent vs propriétaire privilégié",
        "V3C : rejeu 200 ; V3D : agent bloqué OS, rollback privilégié démontré + détecté",
        {
            "first": first.get("status_code"),
            "agent_rollback_attempt": agent_rb,
            "agent_state_dir_list": agent_list,
            "replay_after_agent_rollback": {"status": replay_blocked.get("status_code"), "code": code_rb},
            "chain_floor_before_privileged_rollback": floor,
            "chain_head_after_privileged_rollback": after_head,
            "chain_regression_detected": (floor is not None and after_head != floor),
            "replay_after_privileged_db_rollback": {"status": replay_priv.get("status_code"), "code": code_priv},
            "note": "O_EXCL du marqueur FS : un rollback DB seul ne recrée pas l'effet",
        },
        "LAYERED" if (
            agent_rb["stdout"] in ("PermissionError", "OperationalError")
            and agent_list["stdout"] == "EACCES"
            and replay_blocked.get("status_code") == 403 and code_rb == "NONCE_REUSED"
            and first.get("status_code") == 200
        ) else "NOT_FIXED",
    )

    server.stop()


def main() -> int:
    print("========== PARTIE A — N01-N05 sur V3C PRÉSERVÉ ==========")
    part_a_v3c()
    print()
    print("========== PARTIE B — N01-N05 sur V3D (bac OS) ==========")
    part_b_v3d()

    out = {
        "mission": "AEGIS_V3D_REAL_EFFECT_WITNESS_004",
        "suite": "N01_N05_REPRODUCTION",
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": N_REPORT,
    }
    path = RESULTS / "N01_N05_RESULTS.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwritten: {path}")
    n_repro = sum(1 for r in N_REPORT if r["target"] == "V3C" and r["verdict"] == "REPRODUCED")
    v3d_ok = sum(1 for r in N_REPORT if r["target"] == "V3D"
                 and r["verdict"] in ("FIXED", "SCOPE_MOVED_TO_OS", "LAYERED"))
    print(f"V3C: {n_repro}/5 REPRODUCED | V3D: {v3d_ok}/5 qualifiés")
    return 0 if (n_repro == 5 and v3d_ok == 5) else 1


if __name__ == "__main__":
    raise SystemExit(main())
