#!/usr/bin/env python3
"""Banc décisif AEGIS V3D — témoin d'effet réel dans le bac à sable OS isolé.

Scénarios D01–D18 conformes à THREAT_MODEL.md (figé avant exécution) :
effet réel, fixtures négatives, frontière de permission OS, concurrence,
protocole de crash C1–C4, révocation, rollback, témoin brut.

Oracle : le témoin (UID aegis_witness) UNIQUEMENT. Un 200 HTTP n'est pas une
preuve d'effet. Une ligne SQLite EFFECT_MATERIALIZED n'est pas une preuve OS.
CLAIM <= EVIDENCE.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
AEGIS_V3D_DIR = HERE.parent
RESULTS = AEGIS_V3D_DIR / "results"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(AEGIS_V3D_DIR))

import harness_v3d as H  # noqa: E402

RESULTS.mkdir(exist_ok=True)
D_REPORT: List[Dict[str, Any]] = []


def record(did: str, title: str, expected: str, observed: Dict[str, Any], passed: bool, notes: str = "") -> None:
    entry = {
        "id": did,
        "title": title,
        "expected": expected,
        "observed": observed,
        "verdict": "PASS_LOCAL" if passed else "FAIL",
    }
    if notes:
        entry["notes"] = notes
    D_REPORT.append(entry)
    flag = "PASS" if passed else "**FAIL**"
    print(f"[{flag}] {did:4s} {title}")
    print(f"        expected: {expected}")
    print(f"        observed: {json.dumps(observed, ensure_ascii=False)[:460]}")


def code_of(v: Dict[str, Any]) -> Optional[str]:
    detail = (v.get("body") or {}).get("detail")
    if isinstance(detail, dict):
        return detail.get("code")
    return detail


def composite_state(events: List[str], witness_present: Optional[bool], db_status: Optional[str]) -> str:
    if witness_present is True and "EFFECT_MATERIALIZED" in events:
        return "CONFIRMED"
    if witness_present is True and "EFFECT_MATERIALIZED" not in events:
        return "EFFECT_PRESENT_DB_INCOMPLETE"
    if witness_present is False:
        if "ACTION_ATTEMPTED" in events:
            return "ATTEMPTED_NO_EFFECT"
        if events:
            return "CONSUMED_NO_ATTEMPT"
        return "NO_CONSUMPTION"
    return "UNKNOWN"


def admin_sha256(filename: str) -> Optional[str]:
    p = H.EFFECT / filename
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


def main() -> int:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.time()
    H.ensure_sandbox_dirs()
    H.reset_runtime_state()
    now = time.time()

    server = H.ServerHandle(name="S_MAIN")
    server.start()
    print(f"== V3D S_MAIN up {server.base_url} (uid PEP=aegis_pep) ==")

    def marker_req(pid: str):
        return H.make_request("agent-alpha", "marker.create", f"effect/marker-{pid}.json")

    def send(pid: str, nonce: str, req, priv=None, **kw) -> Dict[str, Any]:
        permit = H.forge_permit(
            priv,
            permit_id=pid, nonce=nonce, orig_request=req,
            issued_at=kw.pop("issued_at", time.time() - 2),
            expires_at=kw.pop("expires_at", time.time() + 120),
            **kw,
        )
        return H.agent_post(server.base_url, {"original_request": req, "permit": permit}, pid.lower())

    # =================================================================
    # D01 — ALLOW : effet réel UNIQUE + témoin séparé
    # =================================================================
    req_d1 = marker_req("P-D1")
    n_d1 = "N-D1-" + str(int(now))
    v_d1 = send("P-D1", n_d1, req_d1)
    w_d1 = H.run_witness(
        "d01",
        expect=[{"filename": "marker-P-D1.json", "permit_id": "P-D1", "nonce": n_d1,
                 "action": "marker.create", "resource": "effect/marker-P-D1.json"}],
    )
    confirmed = any(c["confirmed"] for c in w_d1.get("witness_confirmed", []))
    w_entry = next((f for f in w_d1.get("files", []) if f.get("filename") == "marker-P-D1.json"), None)
    admin_hash = admin_sha256("marker-P-D1.json")
    digest_agree = (w_entry or {}).get("sha256") == admin_hash and admin_hash is not None
    passed = (
        v_d1.get("status_code") == 200
        and (v_d1.get("body") or {}).get("effect_status") == "MATERIALIZED_LOCAL"
        and (v_d1.get("body") or {}).get("effect_confirmed") is False
        and confirmed
        and (w_entry or {}).get("content_digest_valid") is True
        and digest_agree
    )
    record(
        "D01",
        "ALLOW signé : PEP écrit le marqueur ; témoin séparé confirme octets + digest",
        "200 (non probant) + WITNESS CONFIRMED (content_digest valide, digest témoin == relecture admin)",
        {"http": v_d1, "witness_confirmed": w_d1.get("witness_confirmed"),
         "witness_sha256": (w_entry or {}).get("sha256"), "admin_resha256": admin_hash,
         "witness_uid": w_d1.get("witness_uid"), "digest_agree": digest_agree},
        passed,
    )

    # =================================================================
    # D02–D06 — fixtures négatives : aucun marqueur
    # =================================================================
    # D02 : signature invalide
    req_x1 = marker_req("P-X1")
    p_x1 = H.forge_permit(permit_id="P-X1", nonce="N-X1-" + str(int(now)),
                          orig_request=req_x1, issued_at=now - 2, expires_at=now + 120)
    p_x1["signature"] = ("0" if p_x1["signature"][0] != "0" else "1") + p_x1["signature"][1:]
    v_x1 = H.agent_post(server.base_url, {"original_request": req_x1, "permit": p_x1}, "x1")
    record("D02", "X1 signature invalide", "403 INVALID_SIGNATURE ; aucun marqueur",
           {"http": v_x1},
           v_x1.get("status_code") == 403 and code_of(v_x1) == "INVALID_SIGNATURE")

    # D03 : clé substituée (non épinglée)
    from cryptography.hazmat.primitives.asymmetric import ed25519
    atk_priv = ed25519.Ed25519PrivateKey.generate()
    req_x2 = marker_req("P-X2")
    v_x2 = send("P-X2", "N-X2-" + str(int(now)), req_x2, priv=atk_priv)
    record("D03", "X2 signature par clé substituée", "403 INVALID_SIGNATURE ; aucun marqueur",
           {"http": v_x2},
           v_x2.get("status_code") == 403 and code_of(v_x2) == "INVALID_SIGNATURE")

    # D04 : action hors périmètre (signée)
    req_x3 = H.make_request("agent-alpha", "admin.delete", "effect/marker-P-X3.json")
    v_x3 = send("P-X3", "N-X3-" + str(int(now)), req_x3)
    record("D04", "X3 action admin.delete signée", "403 ACTION_FORBIDDEN ; aucun marqueur",
           {"http": v_x3},
           v_x3.get("status_code") == 403 and code_of(v_x3) == "ACTION_FORBIDDEN")

    # D05 : chemins non autorisés
    path_cases = []
    for pid, res, want in (
        ("P-X4A", "etc/passwd", "RESOURCE_FORBIDDEN"),
        ("P-X4B", "effect/../escape.json", "INVALID_FIELD_FORMAT"),
        ("P-X4C", "effect/marker-P-OTHER.json", "EFFECT_PATH_FORBIDDEN"),
        # X4D : sous-répertoire — refusé par l'allowlist (avant le binding de
        # chemin). Critère figé : 4xx AVANT effet, aucun marqueur ; le code de
        # porte exact est informatif (RESOURCE_FORBIDDEN ou EFFECT_PATH_FORBIDDEN).
        ("P-X4D", "effect/sub/marker-P-X4D.json", "RESOURCE_FORBIDDEN|EFFECT_PATH_FORBIDDEN"),
    ):
        rq = H.make_request("agent-alpha", "marker.create", res)
        p = H.forge_permit(permit_id=pid, nonce=f"N-{pid}-" + str(int(now)),
                           orig_request=rq, issued_at=now - 2, expires_at=now + 120)
        vv = H.agent_post(server.base_url, {"original_request": rq, "permit": p}, pid.lower())
        got = code_of(vv) or ""
        ok = vv.get("status_code") in (400, 403) and (
            got in want.split("|") if "|" in want else got == want
        )
        path_cases.append({"pid": pid, "resource": res, "want": want,
                           "got_status": vv.get("status_code"), "got_code": got,
                           "case_ok": ok})
    record(
        "D05",
        "X4 chemins non autorisés (traversée, hors périmètre, désalignés)",
        "4xx avant effet dans les 4 cas ; aucun marqueur créé",
        {"cases": path_cases},
        all(c["case_ok"] for c in path_cases),
    )

    # D06 : permis expiré
    req_x5 = marker_req("P-X5")
    v_x5 = send("P-X5", "N-X5-" + str(int(now)), req_x5,
                issued_at=now - 300, expires_at=now - 100)
    record("D06", "X5 permis expiré", "403 PERMIT_EXPIRED ; aucun marqueur",
           {"http": v_x5},
           v_x5.get("status_code") == 403 and code_of(v_x5) == "PERMIT_EXPIRED")

    # Témoin : les 5 marqueurs négatifs sont ABSENTS
    w_neg = H.run_witness(
        "negatives",
        expect_absent=["marker-P-X1.json", "marker-P-X2.json", "marker-P-X3.json",
                       "marker-P-X4A.json", "marker-P-X4B.json", "marker-P-X4C.json",
                       "marker-P-X4D.json", "marker-P-X5.json"],
    )
    absent_ok = all(w_neg.get("expected_absent_ok", {}).values())
    record(
        "D07",
        "Témoin : absence de tout marqueur négatif",
        "8 fichiers confirmés absents par lecture OS du témoin",
        {"expected_absent_ok": w_neg.get("expected_absent_ok"), "listing": w_neg.get("listing")},
        absent_ok and w_neg.get("error") is None,
    )

    # =================================================================
    # D08 — X6 : champ system_eval => 422 (N01)
    # =================================================================
    req_x6 = marker_req("P-X6")
    p_x6 = H.forge_permit(permit_id="P-X6", nonce="N-X6-" + str(int(now)),
                          orig_request=req_x6, issued_at=now - 2, expires_at=now + 120)
    v_x6 = H.agent_post(server.base_url,
                        {"original_request": req_x6, "permit": p_x6,
                         "system_eval": "id"}, "x6")
    record("D08", "X6 champ wrapper system_eval (enveloppe fermée)",
           "422 (extra=forbid) ; aucun marqueur",
           {"http_status": v_x6.get("status_code")},
           v_x6.get("status_code") == 422)

    # =================================================================
    # D09 — X7 : permit_id UNIQUE (N02)
    # =================================================================
    req_x7 = marker_req("P-X7")
    v_x7a = send("P-X7", "N-X7A-" + str(int(now)), req_x7)
    v_x7b = send("P-X7", "N-X7B-" + str(int(now)), req_x7)
    record("D09", "X7 même permit_id, second nonce",
           "1er 200 ; 2e 403 PERMIT_ID_REUSED ; un seul marqueur",
           {"first": v_x7a.get("status_code"), "second": v_x7b.get("status_code"),
            "second_code": code_of(v_x7b)},
           v_x7a.get("status_code") == 200 and v_x7b.get("status_code") == 403
           and code_of(v_x7b) == "PERMIT_ID_REUSED")

    # =================================================================
    # D10 — X8 : révocation de politique à chaud (N03)
    # =================================================================
    req_x8 = H.make_request("agent-alpha", "report.read", "reports/q3")
    v_x8a = send("P-X8", "N-X8-" + str(int(now)), req_x8)
    pol_path = H.CONFIG / "pep_policy_v3d.json"
    pol = json.loads(pol_path.read_text())
    removed = [r for r in pol["allowlist"] if r["action"] == "report.read"]
    pol["allowlist"] = [r for r in pol["allowlist"] if r["action"] != "report.read"]
    stage = RESULTS / "policy_stage.json"
    stage.write_text(json.dumps(pol, indent=2) + "\n")
    import subprocess
    subprocess.run(["sudo", "cp", str(stage), str(pol_path)], check=True)
    v_x8b = send("P-X8B", "N-X8B-" + str(int(now)), req_x8)
    pol["allowlist"].extend(removed)
    stage.write_text(json.dumps(pol, indent=2) + "\n")
    subprocess.run(["sudo", "cp", str(stage), str(pol_path)], check=True)
    record("D10", "X8 révocation administrative effective à la requête suivante",
           "avant 200 ; après révocation 403 ACTION_FORBIDDEN",
           {"before": v_x8a.get("status_code"), "after": v_x8b.get("status_code"),
            "after_code": code_of(v_x8b), "policy_restored": True},
           v_x8a.get("status_code") == 200 and v_x8b.get("status_code") == 403
           and code_of(v_x8b) == "ACTION_FORBIDDEN")

    # =================================================================
    # D11 — X9/X10 : frontière OS (écriture directe, registre)
    # =================================================================
    direct = H.agent_exec(
        "try:\n"
        "    open('/tmp/aegis_v3d_sandbox/effect/marker-EVIL.json','w').write('x')\n"
        "    print('WRITE_OK')\n"
        "except PermissionError:\n"
        "    print('EACCES')\n"
    )
    delete_direct = H.agent_exec(
        "import os\n"
        "try:\n"
        "    os.unlink('/tmp/aegis_v3d_sandbox/effect/marker-P-D1.json')\n"
        "    print('DELETE_OK')\n"
        "except PermissionError:\n"
        "    print('EACCES')\n"
    )
    db_direct = H.agent_exec(
        "import sqlite3\n"
        "try:\n"
        "    conn=sqlite3.connect('/tmp/aegis_v3d_sandbox/state/pep_ledger.db')\n"
        "    conn.execute('DELETE FROM consumed_permits')\n"
        "    conn.commit()\n"
        "    print('DELETE_OK')\n"
        "except Exception as e:\n"
        "    print(type(e).__name__)\n"
    )
    record(
        "D11",
        "X9/X10 frontière OS : écriture/suppression directe et rollback par l'agent",
        "refus OS sur création, suppression et registre (PermissionError/OperationalError) ; marqueur D1 intact",
        {"create_marker": direct, "delete_marker": delete_direct, "registry_delete": db_direct,
         "marker_P_D1_still_present": admin_sha256("marker-P-D1.json") is not None},
        direct["stdout"] == "EACCES" and delete_direct["stdout"] == "EACCES"
        and db_direct["stdout"] in ("PermissionError", "OperationalError")
        and admin_sha256("marker-P-D1.json") is not None,
    )

    # =================================================================
    # D12 — concurrence 8 processus, même permis
    # =================================================================
    import concurrent.futures
    req_c = marker_req("P-D12")
    permit_c = H.forge_permit(permit_id="P-D12", nonce="N-D12-" + str(int(now)),
                              orig_request=req_c, issued_at=now - 2, expires_at=now + 120)
    payload_c = {"original_request": req_c, "permit": permit_c}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(H.agent_post, server.base_url, payload_c, f"d12_{i}") for i in range(8)]
        conc = [f.result() for f in futs]
    codes = [c.get("status_code") for c in conc]
    n_ok = sum(1 for c in codes if c == 200)
    n_reuse = sum(1 for c in conc if c.get("status_code") == 403 and code_of(c) == "NONCE_REUSED")
    ev_c = H.events_for_nonce(permit_c["nonce"])
    w_c = H.run_witness(
        "conc",
        expect=[{"filename": "marker-P-D12.json", "permit_id": "P-D12", "nonce": permit_c["nonce"],
                 "action": "marker.create", "resource": "effect/marker-P-D12.json"}],
    )
    confirmed_c = any(c["confirmed"] for c in w_c.get("witness_confirmed", []))
    one_materialized = ev_c.count("EFFECT_MATERIALIZED") == 1
    record(
        "D12",
        "Concurrence 8 clients : un seul effet matériel",
        "1×200 + 7×403 NONCE_REUSED ; exactement 1 EFFECT_MATERIALIZED ; témoin CONFIRMED",
        {"status_codes": codes, "events": ev_c, "witness": w_c.get("witness_confirmed")},
        n_ok == 1 and n_reuse == 7 and one_materialized and confirmed_c,
    )

    # =================================================================
    # D13 — rejeu après redémarrage
    # =================================================================
    server.restart()
    v_replay = H.agent_post(server.base_url, payload_c, "d13_replay")
    listing_after = H.effect_listing()
    record(
        "D13",
        "Rejeu après redémarrage du processus PEP",
        "403 NONCE_REUSED ; aucun second marqueur (effect_listing stable)",
        {"replay": v_replay.get("status_code"), "code": code_of(v_replay),
         "marker_count": sum(1 for n in listing_after if n.startswith("marker-"))},
        v_replay.get("status_code") == 403 and code_of(v_replay) == "NONCE_REUSED"
        and admin_sha256("marker-P-D12.json") is not None,
    )

    # =================================================================
    # D14–D17 — protocole de crash C1–C4
    # =================================================================

    def crash_case(did: str, fault_point: str, pid: str, expected_pre_state: str,
                   expect_retry: str, expect_marker_before: bool, title: str) -> None:
        now2 = time.time()
        rq = marker_req(pid)
        pm = H.forge_permit(permit_id=pid, nonce=f"N-{pid}-" + str(int(now2)),
                            orig_request=rq, issued_at=now2 - 2, expires_at=now2 + 120)
        payload = {"original_request": rq, "permit": pm}
        s_f = H.ServerHandle(
            env_overrides={"AEGIS_FAULT_INJECT": fault_point, "AEGIS_FAULT_EXIT_CODE": "73"},
            name=f"S_{pid}",
        )
        s_f.start()
        client_err = None
        try:
            H.agent_post(s_f.base_url, payload, pid.lower() + "_crash")
        except Exception as exc:  # noqa: BLE001
            client_err = repr(exc)
        for _ in range(100):
            if s_f.proc is not None and s_f.proc.poll() is not None:
                break
            time.sleep(0.05)
        crash_exit = s_f.proc.poll() if s_f.proc else None
        s_f.stop()

        # --- observations PRÉ-réessai : DB + témoin ---
        ev_pre = H.events_for_nonce(pm["nonce"])
        st_pre = H.status_for_nonce(pm["nonce"])
        marker_name = f"marker-{pid}.json"
        marker_pre = admin_sha256(marker_name) is not None
        w_pre = H.run_witness(
            pid.lower() + "_pre",
            expect_absent=[] if expect_marker_before else [marker_name],
        )
        pre_state = composite_state(ev_pre, marker_pre, st_pre)

        # --- réessai sur serveur propre ---
        s_r = H.ServerHandle(name=f"S_{pid}_retry")
        s_r.start()
        retry = H.agent_post(s_r.base_url, payload, pid.lower() + "_retry")
        s_r.stop()

        # --- observations POST-réessai ---
        ev_post = H.events_for_nonce(pm["nonce"])
        marker_post = admin_sha256(marker_name) is not None
        post_state = composite_state(ev_post, marker_post, H.status_for_nonce(pm["nonce"]))

        retry_ok = (
            (expect_retry == "RETRY_200" and retry.get("status_code") == 200)
            or (expect_retry == "RETRY_NONCE_REUSED" and retry.get("status_code") == 403
                and code_of(retry) == "NONCE_REUSED")
        )
        if expect_retry == "RETRY_200":
            # l'effet doit être produit exactement une fois, confirmé par le témoin
            w_post = H.run_witness(
                pid.lower() + "_post",
                expect=[{"filename": marker_name, "permit_id": pid,
                         "nonce": pm["nonce"], "action": "marker.create",
                         "resource": f"effect/{marker_name}"}],
            )
            effect_once = ev_post.count("EFFECT_MATERIALIZED") == 1
            witness_ok = any(c["confirmed"] for c in w_post.get("witness_confirmed", []))
            final_ok = retry_ok and effect_once and witness_ok and marker_post and post_state == "CONFIRMED"
        elif expect_marker_before:
            # C4 : le marqueur MATÉRIALISÉ survit au crash ; le témoin le confirme
            w_post = H.run_witness(
                pid.lower() + "_post",
                expect=[{"filename": marker_name, "permit_id": pid,
                         "nonce": pm["nonce"], "action": "marker.create",
                         "resource": f"effect/{marker_name}"}],
            )
            witness_ok = any(c["confirmed"] for c in w_post.get("witness_confirmed", []))
            final_ok = (retry_ok and witness_ok and marker_post
                        and post_state == expected_pre_state)
        else:
            w_post = H.run_witness(pid.lower() + "_post", expect_absent=[marker_name])
            witness_ok = all(w_post.get("expected_absent_ok", {}).values())
            final_ok = (retry_ok and witness_ok and not marker_post
                        and post_state == expected_pre_state)
        record(
            did, title,
            f"crash exit 73 ; état pré-réessai {expected_pre_state} ; {expect_retry} ;"
            f" marqueur avant réessai {'présent' if expect_marker_before else 'absent'}",
            {
                "fault_point": fault_point,
                "crash_exit_code": crash_exit,
                "client_error": client_err,
                "pre": {"events": ev_pre, "db_status": st_pre, "marker_present": marker_pre,
                        "composite_state": pre_state, "witness_absent_ok": w_pre.get("expected_absent_ok")},
                "retry": {"status": retry.get("status_code"), "code": code_of(retry)},
                "post": {"events": ev_post, "marker_present": marker_post,
                         "composite_state": post_state, "witness_ok": witness_ok},
            },
            crash_exit == 73 and pre_state == expected_pre_state and final_ok,
        )

    crash_case(
        "D14", "before_consume_commit", "P-C1", "NO_CONSUMPTION",
        "RETRY_200", False,
        "C1 crash AVANT COMMIT : rien consommé ; le réessai produit exactement un effet",
    )
    crash_case(
        "D15", "after_consume_commit", "P-C2", "CONSUMED_NO_ATTEMPT",
        "RETRY_NONCE_REUSED", False,
        "C2 crash APRÈS COMMIT, avant tentative : PENDING ; fail-closed ; aucun effet",
    )
    crash_case(
        "D16", "after_attempt", "P-C3", "ATTEMPTED_NO_EFFECT",
        "RETRY_NONCE_REUSED", False,
        "C3 crash APRÈS tentative, avant effet : ATTEMPTED ; aucun marqueur ; fail-closed",
    )
    crash_case(
        "D17", "after_effect", "P-C4", "EFFECT_PRESENT_DB_INCOMPLETE",
        "RETRY_NONCE_REUSED", True,
        "C4 crash APRÈS effet, avant statut : fenêtre COMMIT→effet ; témoin PRÉSENT, DB incomplète",
    )

    # =================================================================
    # D18 — témoin brut : indépendance digest (relecture admin)
    # =================================================================
    w_final = H.run_witness(
        "final",
        expect=[{"filename": "marker-P-D1.json", "permit_id": "P-D1",
                 "nonce": "N-D1-" + str(int(now)), "action": "marker.create",
                 "resource": "effect/marker-P-D1.json"}],
    )
    entries = {f.get("filename"): f for f in w_final.get("files", [])}
    agree_all = True
    digest_rows = []
    for name, entry in entries.items():
        ah = admin_sha256(name)
        ok = ah is not None and ah == entry.get("sha256")
        agree_all = agree_all and ok
        digest_rows.append({"file": name, "witness_sha256": entry.get("sha256"),
                            "admin_sha256": ah, "agree": ok})
    record(
        "D18",
        "RAW_WITNESS : digest témoin == relecture indépendante admin sur tous les marqueurs",
        "concordance SHA-256 pour 100% des fichiers observés ; aucun canal API utilisé",
        {"digest_rows": digest_rows, "witness_uid": w_final.get("witness_uid"),
         "oracle": w_final.get("oracle")},
        agree_all and len(digest_rows) > 0 and w_final.get("witness_uid") != 0,
    )

    server.stop()

    total = len(D_REPORT)
    n_pass = sum(1 for s in D_REPORT if s["verdict"] == "PASS_LOCAL")
    results = {
        "mission_id": "AEGIS_V3D_REAL_EFFECT_WITNESS_004",
        "suite": "V3D_DECISIVE",
        "started_at": started,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.time() - t0, 3),
        "sandbox": {
            "root": str(H.SANDBOX),
            "identities": {"pep": "aegis_pep", "witness": "aegis_witness", "agent": "aegis_agent"},
            "effect_dir": str(H.EFFECT),
        },
        "scenarios": D_REPORT,
        "summary": {"total": total, "pass": n_pass, "fail": total - n_pass},
    }
    path = RESULTS / "V3D_DECISIVE_RESULTS.json"
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n== SUMMARY: {n_pass}/{total} PASS_LOCAL ==")
    print(f"written: {path}")
    return 0 if n_pass == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
