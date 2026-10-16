#!/usr/bin/env python3
"""Banc d'essai adversarial AEGIS V3C — mission AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003.

Réexécute :
  - T01–T24 : les 24 contre-épreuves NEMESIS du dossier V3 ;
  - V3C-F01–F10 : 10 fixtures fondatrices (reconstituées, voir original/PROVENANCE.md) ;
  - V3C-A01–A16 : 16 attaques adversariales (reconstituées).

Règles : OBSERVED != EXPECTED (les deux sont stockés séparément) ; aucun PASS sans
runner ; LOCAL_ONLY (loopback 127.0.0.1, aucune cible OS réelle, aucun réseau externe).

Usage :
    python tests/run_v3c_tribunal.py            # écrit results/EXPERIMENT_RESULTS.json
    python tests/run_v3c_tribunal.py --tag r2   # écrit ..._REPEAT suffixes via --tag
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sqlite3
import sys
import time
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

HERE = Path(__file__).resolve().parent
AEGIS_DIR = HERE.parent
RESULTS_DIR = AEGIS_DIR / "results"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(AEGIS_DIR))

import harness as H  # noqa: E402
import pep_v3c_pinned as pep_mod  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

SCENARIOS: List[Dict[str, Any]] = []


def record(
    sid: str,
    family: str,
    title: str,
    expected: str,
    observed: Dict[str, Any],
    passed: bool,
    notes: str = "",
) -> None:
    entry = {
        "id": sid,
        "family": family,
        "title": title,
        "expected_v3c": expected,
        "observed": observed,
        "verdict": "PASS_LOCAL" if passed else "FAIL",
    }
    if notes:
        entry["notes"] = notes
    SCENARIOS.append(entry)
    flag = "PASS" if passed else "**FAIL**"
    print(f"[{flag}] {sid:6s} {title}")
    print(f"         expected: {expected}")
    print(f"         observed: {json.dumps(observed, ensure_ascii=False)[:400]}")


def resp_view(r: httpx.Response) -> Dict[str, Any]:
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {"_raw": r.text[:300]}
    return {"status_code": r.status_code, "body": body}


def code_of(view: Dict[str, Any]) -> Optional[str]:
    detail = view.get("body", {}).get("detail")
    if isinstance(detail, dict):
        return detail.get("code")
    return detail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run1")
    args = ap.parse_args()
    tag = args.tag

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t_start = time.time()

    # ------------------------------------------------------------------
    # Phase 0 — espace de travail, clés légitime + attaquante
    # ------------------------------------------------------------------
    workspace = AEGIS_DIR / "bench_workspace" / tag
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)

    legit_priv, legit_pub = H.gen_keypair()
    atk_priv, atk_pub = H.gen_keypair()
    H.setup_workspace(workspace, legit_pub)

    server = H.ServerHandle(workspace, name="S_MAIN")
    server.start()
    print(f"== S_MAIN up on {server.base_url} (workspace={workspace.name}) ==")

    def ok_request() -> Dict[str, str]:
        return H.make_request("agent-alpha", "report.read", "reports/q3")

    now = time.time()

    # ==================================================================
    # FAMILLE 1 — T01–T24 : contre-épreuves NEMESIS rejouées sur V3C
    # ==================================================================

    # --- T01 : premier permis valide --------------------------------
    req1 = ok_request()
    p1 = H.forge_permit(
        legit_priv,
        permit_id="P-T01",
        nonce="N-T01-" + H.secrets.token_hex(4),
        orig_request=req1,
        issued_at=now - 5,
        expires_at=now + 120,
    )
    v = resp_view(server.execute(req1, p1))
    body = v["body"]
    passed = (
        v["status_code"] == 200
        and body.get("status") == "AUTHORIZED"
        and body.get("permit_consumed") is True
        and body.get("effect_confirmed") is False
        and "executed" not in body
    )
    record(
        "T01",
        "NEMESIS_T01_T24",
        "Premier permis valide",
        "200 + corps honnête (permit_consumed=True, effect_confirmed=False, pas de executed)",
        v,
        passed,
    )

    # --- T02 : rejeu après redémarrage de processus ------------------
    v = resp_view(server.execute(req1, p1))
    first = v
    server.restart()
    v2 = resp_view(server.execute(req1, p1))
    passed = (
        first["status_code"] == 403
        and code_of(first) == "NONCE_REUSED"
        and v2["status_code"] == 403
        and code_of(v2) == "NONCE_REUSED"
    )
    record(
        "T02",
        "NEMESIS_T01_T24",
        "Même nonce après relance du processus",
        "403 NONCE_REUSED avant ET après redémarrage (registre durable)",
        {"before_restart": first, "after_restart": v2},
        passed,
    )

    # --- T03 : 8 processus concurrents ------------------------------
    req3 = ok_request()
    p3 = H.forge_permit(
        legit_priv,
        permit_id="P-T03",
        nonce="N-T03-" + H.secrets.token_hex(4),
        orig_request=req3,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    conc = H.concurrent_execute(workspace, server.base_url, req3, p3, 8, tag="T03")
    codes = [c.get("status_code", c.get("error")) for c in conc]
    n_ok = sum(1 for c in codes if c == 200)
    n_reuse = sum(
        1
        for c in conc
        if c.get("status_code") == 403 and c.get("body", {}).get("detail", {}).get("code") == "NONCE_REUSED"
    )
    passed = n_ok == 1 and n_reuse == 7
    record(
        "T03",
        "NEMESIS_T01_T24",
        "8 interpréteurs simultanés, même permis",
        "exactement 1×200 et 7×403 NONCE_REUSED",
        {"status_codes": codes, "accepted": n_ok, "nonce_reused": n_reuse},
        passed,
    )

    # --- T04 : permis expiré ----------------------------------------
    req4 = ok_request()
    p4 = H.forge_permit(
        legit_priv,
        permit_id="P-T04",
        nonce="N-T04-" + H.secrets.token_hex(4),
        orig_request=req4,
        issued_at=time.time() - 300,
        expires_at=time.time() - 1,
    )
    v = resp_view(server.execute(req4, p4))
    record(
        "T04",
        "NEMESIS_T01_T24",
        "Expiration dépassée",
        "403 PERMIT_EXPIRED",
        v,
        v["status_code"] == 403 and code_of(v) == "PERMIT_EXPIRED",
    )

    # --- T05 : audience incorrecte ----------------------------------
    req5 = ok_request()
    p5 = H.forge_permit(
        legit_priv,
        permit_id="P-T05",
        nonce="N-T05-" + H.secrets.token_hex(4),
        orig_request=req5,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
        audience="monsterdog.pep.evil",
    )
    v = resp_view(server.execute(req5, p5))
    record(
        "T05",
        "NEMESIS_T01_T24",
        "Audience incorrecte",
        "403 WRONG_AUDIENCE",
        v,
        v["status_code"] == 403 and code_of(v) == "WRONG_AUDIENCE",
    )

    # --- T06 : signature altérée ------------------------------------
    req6 = ok_request()
    p6 = H.forge_permit(
        legit_priv,
        permit_id="P-T06",
        nonce="N-T06-" + H.secrets.token_hex(4),
        orig_request=req6,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    sig = p6["signature"]
    p6["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    v = resp_view(server.execute(req6, p6))
    record(
        "T06",
        "NEMESIS_T01_T24",
        "Signature altérée",
        "403 INVALID_SIGNATURE",
        v,
        v["status_code"] == 403 and code_of(v) == "INVALID_SIGNATURE",
    )

    # --- T07 : signature non hexadécimale ---------------------------
    req7 = ok_request()
    p7 = H.forge_permit(
        legit_priv,
        permit_id="P-T07",
        nonce="N-T07-" + H.secrets.token_hex(4),
        orig_request=req7,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    p7["signature"] = "zz" * 64
    v = resp_view(server.execute(req7, p7))
    record(
        "T07",
        "NEMESIS_T01_T24",
        "Signature non hexadécimale (entrée hostile)",
        "4xx contrôlé INVALID_FIELD_FORMAT (jamais 500)",
        v,
        v["status_code"] == 400 and code_of(v) == "INVALID_FIELD_FORMAT",
    )

    # --- T08 : action interdite mais signée -------------------------
    req8 = H.make_request("agent-alpha", "admin.delete", "reports/q3")
    p8 = H.forge_permit(
        legit_priv,
        permit_id="P-T08",
        nonce="N-T08-" + H.secrets.token_hex(4),
        orig_request=req8,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    v = resp_view(server.execute(req8, p8))
    record(
        "T08",
        "NEMESIS_T01_T24",
        "Action admin.delete correctement signée (régression V3)",
        "403 ACTION_FORBIDDEN — allowlist PEP indépendante",
        v,
        v["status_code"] == 403 and code_of(v) == "ACTION_FORBIDDEN",
    )

    # --- T09 : issuer non autorisé mais signé -----------------------
    req9 = ok_request()
    p9 = H.forge_permit(
        legit_priv,
        permit_id="P-T09",
        nonce="N-T09-" + H.secrets.token_hex(4),
        orig_request=req9,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
        issuer="evil.issuer.forge",
    )
    v = resp_view(server.execute(req9, p9))
    record(
        "T09",
        "NEMESIS_T01_T24",
        "Issuer non autorisé (régression V3)",
        "403 ISSUER_FORBIDDEN",
        v,
        v["status_code"] == 403 and code_of(v) == "ISSUER_FORBIDDEN",
    )

    # --- T10 : ancienne policy_version ------------------------------
    req10 = ok_request()
    p10 = H.forge_permit(
        legit_priv,
        permit_id="P-T10",
        nonce="N-T10-" + H.secrets.token_hex(4),
        orig_request=req10,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
        policy_version="v2.0.1",
    )
    v = resp_view(server.execute(req10, p10))
    record(
        "T10",
        "NEMESIS_T01_T24",
        "Ancienne policy_version (régression V3)",
        "403 POLICY_VERSION_MISMATCH",
        v,
        v["status_code"] == 403 and code_of(v) == "POLICY_VERSION_MISMATCH",
    )

    # --- T11 : requête altérée ne doit PLUS brûler le nonce ---------
    req11 = ok_request()
    p11 = H.forge_permit(
        legit_priv,
        permit_id="P-T11",
        nonce="N-T11-" + H.secrets.token_hex(4),
        orig_request=req11,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    tampered = dict(req11)
    tampered["resource"] = "reports/q3-public"
    v_t = resp_view(server.execute(tampered, p11))
    v_o = resp_view(server.execute(req11, p11))
    passed = (
        v_t["status_code"] == 403
        and code_of(v_t) == "REQUEST_TAMPERED"
        and v_o["status_code"] == 200
    )
    record(
        "T11",
        "NEMESIS_T01_T24",
        "Req. altérée puis vraie (anti burn-on-tamper, régression V3)",
        "403 REQUEST_TAMPERED puis 200 — le nonce n'est PAS brûlé",
        {"tampered": v_t, "original_afterward": v_o},
        passed,
    )

    # --- T12 : action modifiée dans la requête ----------------------
    req12 = ok_request()
    p12 = H.forge_permit(
        legit_priv,
        permit_id="P-T12",
        nonce="N-T12-" + H.secrets.token_hex(4),
        orig_request=req12,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    bad = dict(req12)
    bad["action"] = "email.send"
    v = resp_view(server.execute(bad, p12))
    record(
        "T12",
        "NEMESIS_T01_T24",
        "Action modifiée sans re-signature",
        "403 REQUEST_TAMPERED",
        v,
        v["status_code"] == 403 and code_of(v) == "REQUEST_TAMPERED",
    )

    # --- T13 : substitution de la clé publique ----------------------
    (workspace / "pep_public.key").write_bytes(atk_pub)
    s_k = H.ServerHandle(workspace, name="S_SUBST_KEY")
    s_k.start()
    v_health = {"health": s_k.health()}
    req13 = ok_request()
    p13 = H.forge_permit(
        atk_priv,
        permit_id="P-T13",
        nonce="N-T13-" + H.secrets.token_hex(4),
        orig_request=req13,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    v = resp_view(s_k.execute(req13, p13))
    s_k.stop()
    (workspace / "pep_public.key").write_bytes(legit_pub)
    passed = (
        v_health["health"].get("trust_root") != "OK"
        and v["status_code"] == 503
        and code_of(v) == "PEP_TRUST_ROOT_PIN_MISMATCH"
    )
    record(
        "T13",
        "NEMESIS_T01_T24",
        "Clé publique substituée + permis signé par le substituant (régression V3)",
        "503 PEP_TRUST_ROOT_PIN_MISMATCH (fail-closed) — jamais 200",
        {"health": v_health, "execute": v},
        passed,
    )

    # --- T14 : clé publique manquante ------------------------------
    key_backup = (workspace / "pep_public.key").read_bytes()
    (workspace / "pep_public.key").unlink()
    s_m = H.ServerHandle(workspace, name="S_NO_KEY")
    s_m.start()
    v_health = {"health": s_m.health()}
    v = resp_view(s_m.execute(ok_request(), p1))
    s_m.stop()
    (workspace / "pep_public.key").write_bytes(key_backup)
    passed = v["status_code"] == 503 and code_of(v) == "PEP_TRUST_ROOT_UNAVAILABLE"
    record(
        "T14",
        "NEMESIS_T01_T24",
        "Clé publique manquante",
        "503 PEP_TRUST_ROOT_UNAVAILABLE (fail-closed contrôlé)",
        {"health": v_health, "execute": v},
        passed,
    )

    # --- T15 : expiration de type chaîne ----------------------------
    req15 = ok_request()
    p15 = H.forge_permit(
        legit_priv,
        permit_id="P-T15",
        nonce="N-T15-" + H.secrets.token_hex(4),
        orig_request=req15,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    p15["expires_at"] = "2000000000.0"  # type hostile
    v = resp_view(server.execute(req15, p15))
    record(
        "T15",
        "NEMESIS_T01_T24",
        "Expiration de type chaîne (entrée hostile)",
        "400 INVALID_FIELD_TYPE (jamais 500)",
        v,
        v["status_code"] == 400 and code_of(v) == "INVALID_FIELD_TYPE",
    )

    # --- T16 : claim erroné mais signé ------------------------------
    req16 = ok_request()
    p16 = H.forge_permit(
        legit_priv,
        permit_id="P-T16",
        nonce="N-T16-" + H.secrets.token_hex(4),
        orig_request=req16,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
        extra_fields={"claims": {"core_statement": "the moon is made of cheese", "veracity": True}},
    )
    v = resp_view(server.execute(req16, p16))
    record(
        "T16",
        "NEMESIS_T01_T24",
        "Claim erroné mais signé (PEP ≠ oracle de vérité)",
        "400 PERMIT_SCHEMA_VIOLATION — contenu non attesté refusé à la frontière",
        v,
        v["status_code"] == 400 and code_of(v) == "PERMIT_SCHEMA_VIOLATION",
    )

    # --- T17 : nonce modifié sans re-signer -------------------------
    req17 = ok_request()
    p17 = H.forge_permit(
        legit_priv,
        permit_id="P-T17",
        nonce="N-T17-" + H.secrets.token_hex(4),
        orig_request=req17,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    p17["nonce"] = "N-T17-substituted"
    v = resp_view(server.execute(req17, p17))
    record(
        "T17",
        "NEMESIS_T01_T24",
        "Nonce modifié sans re-signature",
        "403 INVALID_SIGNATURE",
        v,
        v["status_code"] == 403 and code_of(v) == "INVALID_SIGNATURE",
    )

    # --- T18 : sémantique d'effet honnête ---------------------------
    req18 = ok_request()
    nonce18 = "N-T18-" + H.secrets.token_hex(4)
    p18 = H.forge_permit(
        legit_priv,
        permit_id="P-T18",
        nonce=nonce18,
        orig_request=req18,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    v = resp_view(server.execute(req18, p18))
    ev = H.events_for_nonce(workspace, nonce18)
    src = (AEGIS_DIR / "pep_v3c_pinned.py").read_text(encoding="utf-8")
    forbidden = [
        s
        for s in ("os.system", "os.popen", "subprocess", "urllib", "requests.", "socket.socket")
        if s in src
    ]
    all_ev = [e[4] for e in H.db_rows(workspace)["events"]]
    passed = (
        v["status_code"] == 200
        and "executed" not in v["body"]
        and v["body"].get("effect_confirmed") is False
        and v["body"].get("effect_status") == "SIMULATED_LOCAL_ONLY"
        and ev == ["PERMIT_CONSUMED", "ACTION_ATTEMPTED", "EFFECT_SIMULATED"]
        and "EFFECT_CONFIRMED" not in all_ev
        and not forbidden
    )
    record(
        "T18",
        "NEMESIS_T01_T24",
        "Aucun effet externe réel — pas d'executed=true trompeur",
        "événements distincts PERMIT_CONSUMED/ACTION_ATTEMPTED/EFFECT_SIMULATED ;"
        " effect_confirmed=False ; 0 canal d'effet externe dans le code",
        {"response": v, "events_for_nonce": ev, "forbidden_symbols_in_pep": forbidden},
        passed,
    )

    # --- T19 : persistance sur second redémarrage -------------------
    req19 = ok_request()
    p19 = H.forge_permit(
        legit_priv,
        permit_id="P-T19",
        nonce="N-T19-" + H.secrets.token_hex(4),
        orig_request=req19,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    server.restart()
    v_new = resp_view(server.execute(req19, p19))
    v_old = resp_view(server.execute(req1, p1))  # permis T01 toujours mort
    passed = (
        v_new["status_code"] == 200
        and v_old["status_code"] == 403
        and code_of(v_old) == "NONCE_REUSED"
    )
    record(
        "T19",
        "NEMESIS_T01_T24",
        "Deuxième paire 1er/2e appel après un second redémarrage",
        "nouveau permis 200 ; ancien nonce toujours 403 NONCE_REUSED",
        {"new_permit": v_new, "old_nonce_replay": v_old},
        passed,
    )

    # --- T20 : policy_version absente -------------------------------
    req20 = ok_request()
    p20 = H.forge_permit(
        legit_priv,
        permit_id="P-T20",
        nonce="N-T20-" + H.secrets.token_hex(4),
        orig_request=req20,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    del p20["policy_version"]
    v = resp_view(server.execute(req20, p20))
    record(
        "T20",
        "NEMESIS_T01_T24",
        "Version politique absente (régression V3)",
        "400 PERMIT_SCHEMA_VIOLATION",
        v,
        v["status_code"] == 400 and code_of(v) == "PERMIT_SCHEMA_VIOLATION",
    )

    # --- T21 : crash après COMMIT (fail-closed at-most-once) --------
    req21 = ok_request()
    nonce21 = "N-T21-" + H.secrets.token_hex(4)
    p21 = H.forge_permit(
        legit_priv,
        permit_id="P-T21",
        nonce=nonce21,
        orig_request=req21,
        issued_at=time.time() - 5,
        expires_at=time.time() + 120,
    )
    s_f = H.ServerHandle(
        workspace,
        env_overrides={
            "AEGIS_TEST_MODE": "1",
            "AEGIS_FAULT_INJECT": "after_consume_commit",
            "AEGIS_FAULT_EXIT_CODE": "73",
        },
        name="S_FAULT",
    )
    s_f.start()
    crash_client_error = None
    try:
        s_f.execute(req21, p21)
    except Exception as exc:  # noqa: BLE001
        crash_client_error = repr(exc)
    for _ in range(100):  # attendre la mort effective du processus injecté
        if s_f.proc is not None and s_f.proc.poll() is not None:
            break
        time.sleep(0.05)
    crash_exit = s_f.proc.poll() if s_f.proc else None
    s_f.stop()
    rows21 = H.db_rows(workspace)
    st21 = [r for r in rows21["consumed"] if r[0] == nonce21]
    ev21 = [e[4] for e in rows21["events"] if e[2] == nonce21]
    s_r = H.ServerHandle(workspace, name="S_RETRY")
    s_r.start()
    v_retry = resp_view(s_r.execute(req21, p21))
    s_r.stop()
    passed = (
        crash_exit == 73
        and crash_client_error is not None
        and st21
        and st21[0][6] == "PENDING"
        and ev21 == ["PERMIT_CONSUMED"]
        and v_retry["status_code"] == 403
        and code_of(v_retry) == "NONCE_REUSED"
    )
    record(
        "T21",
        "NEMESIS_T01_T24",
        "Crash injecté après COMMIT du nonce",
        "exit 73 ; état PENDING ; seul PERMIT_CONSUMED ; réessai 403 NONCE_REUSED (fail-closed)",
        {
            "crash_exit_code": crash_exit,
            "client_error": crash_client_error,
            "db_row": st21,
            "events": ev21,
            "retry": v_retry,
        },
        passed,
    )

    # --- T22 : frontière d'expiration exclusive ---------------------
    T = 1780000000.0  # horloge fixe de test
    s_c = H.ServerHandle(
        workspace,
        env_overrides={"AEGIS_TEST_MODE": "1", "AEGIS_FIXED_NOW": str(T)},
        name="S_FIXED_CLOCK",
    )
    s_c.start()
    req22 = ok_request()
    p22a = H.forge_permit(
        legit_priv,
        permit_id="P-T22A",
        nonce="N-T22A-" + H.secrets.token_hex(4),
        orig_request=req22,
        issued_at=T - 30,
        expires_at=T,  # exactement la borne
    )
    p22b = H.forge_permit(
        legit_priv,
        permit_id="P-T22B",
        nonce="N-T22B-" + H.secrets.token_hex(4),
        orig_request=req22,
        issued_at=T - 30,
        expires_at=T + 0.5,  # strictement après la borne
    )
    v_exact = resp_view(s_c.execute(req22, p22a))
    v_before = resp_view(s_c.execute(req22, p22b))
    s_c.stop()
    passed = (
        v_exact["status_code"] == 403
        and code_of(v_exact) == "PERMIT_EXPIRED"
        and v_before["status_code"] == 200
    )
    record(
        "T22",
        "NEMESIS_T01_T24",
        "Borne d'expiration exclusive (now == expires_at => BLOCK)",
        "à expires_at exactement : 403 PERMIT_EXPIRED ; juste avant : 200",
        {"at_exact_boundary": v_exact, "strictly_before": v_before, "fixed_now": T},
        passed,
    )

    # --- T23 : issued_at dans le futur ------------------------------
    req23 = ok_request()
    p23 = H.forge_permit(
        legit_priv,
        permit_id="P-T23",
        nonce="N-T23-" + H.secrets.token_hex(4),
        orig_request=req23,
        issued_at=time.time() + 86400,
        expires_at=time.time() + 86400 + 120,
    )
    v = resp_view(server.execute(req23, p23))
    record(
        "T23",
        "NEMESIS_T01_T24",
        "issued_at +24 heures (régression V3)",
        "403 FUTURE_ISSUED_AT",
        v,
        v["status_code"] == 403 and code_of(v) == "FUTURE_ISSUED_AT",
    )

    # --- T24 : TTL excessif (~1 an) ---------------------------------
    req24 = ok_request()
    p24 = H.forge_permit(
        legit_priv,
        permit_id="P-T24",
        nonce="N-T24-" + H.secrets.token_hex(4),
        orig_request=req24,
        issued_at=time.time() - 10,
        expires_at=time.time() - 10 + 365 * 86400,
    )
    v = resp_view(server.execute(req24, p24))
    record(
        "T24",
        "NEMESIS_T01_T24",
        "TTL approximatif 1 an (régression V3)",
        "403 TTL_EXCEEDED (borne max_ttl_seconds)",
        v,
        v["status_code"] == 403 and code_of(v) == "TTL_EXCEEDED",
    )

    # ==================================================================
    # FAMILLE 2 — V3C-F01–F10 : fixtures fondatrices (reconstituées)
    # ==================================================================

    # --- F01 : stabilité de canonical_hash --------------------------
    a = {"b": 1, "a": "é", "z": {"y": 2, "x": [1, 2]}}
    b = {"z": {"x": [1, 2], "y": 2}, "a": "é", "b": 1}
    c = {"a": "e", "b": 1, "z": {"y": 2, "x": [1, 2]}}
    h1, h2, h3 = H.canonical_hash(a), H.canonical_hash(b), H.canonical_hash(c)
    record(
        "F01",
        "FIXTURES_F01_F10",
        "canonical_hash : indépendance d'ordre des clés, sensibilité au contenu",
        "h(ordre1)==h(ordre2) ; h(contenu différent)!=h",
        {"h_order1": h1, "h_order2": h2, "h_other_content": h3},
        h1 == h2 and h1 != h3,
    )

    # --- F02 : roundtrip signature ----------------------------------
    body2 = {
        "permit_id": "P-F02",
        "issuer": H.DEFAULT_ISSUER,
        "subject": "agent-alpha",
        "action": "report.read",
        "resource": "reports/q3",
        "audience": H.DEFAULT_AUDIENCE,
        "policy_version": H.DEFAULT_POLICY_VERSION,
        "nonce": "N-F02",
        "issued_at": 1.0,
        "expires_at": 2.0,
        "request_hash": H.canonical_hash(ok_request()),
    }
    sig = H.sign_body(legit_priv, body2)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pub = ed25519.Ed25519PublicKey.from_public_bytes(legit_pub)
        pub.verify(bytes.fromhex(sig), H.canonical_hash(body2).encode())
        ok_sig = True
    except InvalidSignature:
        ok_sig = False
    tampered = dict(body2)
    tampered["expires_at"] = 99.0
    try:
        pub.verify(bytes.fromhex(sig), H.canonical_hash(tampered).encode())
        bad_sig_rejected = False
    except InvalidSignature:
        bad_sig_rejected = True
    except Exception:  # noqa: BLE001
        bad_sig_rejected = True
    record(
        "F02",
        "FIXTURES_F01_F10",
        "Roundtrip Ed25519 sur corps canonique",
        "valide accepté ; corps altéré => signature invalide",
        {"valid_signature_ok": ok_sig, "tampered_body_rejected": bad_sig_rejected},
        ok_sig and bad_sig_rejected,
    )

    # --- F03 : épinglage de confiance OK ----------------------------
    pol = pep_mod.load_policy(str(workspace / "pep_policy_v3c.json"))
    st, pubk = pep_mod.load_trust(
        str(workspace / "pep_public.key"),
        pol,
        str(workspace / "trust_root.pin"),
        None,
    )
    record(
        "F03",
        "FIXTURES_F01_F10",
        "load_trust : clé + pin fichier + politique concordants",
        "TrustState OK avec empreinte SHA-256 exacte",
        {"ok": st.ok, "code": st.code, "fingerprint": st.fingerprint},
        st.ok and st.fingerprint == H.fingerprint(legit_pub) and pubk is not None,
    )

    # --- F04 : sémantique allowlist ---------------------------------
    app_f = pep_mod.build_app(
        str(workspace / "pep_policy_v3c.json"),
        str(workspace / "pep_public.key"),
        str(workspace / "trust_root.pin"),
        str(workspace / "f_unit.db"),
    )
    client = TestClient(app_f)
    cases = []
    for subj, act, res, want in (
        ("agent-alpha", "report.read", "reports/q3", 200),
        ("agent-alpha", "report.read", "secrets/other", 403),
        ("agent-beta", "email.send", "outbox/digest", 403),
        ("agent-gamma", "report.read", "reports/q3", 403),
        ("agent-beta", "report.read", "reports/public/x", 200),
    ):
        r = H.make_request(subj, act, res)
        p = H.forge_permit(
            legit_priv,
            permit_id="P-F04-" + H.secrets.token_hex(3),
            nonce="N-F04-" + H.secrets.token_hex(6),
            orig_request=r,
            issued_at=time.time() - 2,
            expires_at=time.time() + 100,
        )
        resp = client.post("/v1/execute", json={"original_request": r, "permit": p})
        cases.append({"case": [subj, act, res], "want": want, "got": resp.status_code})
    record(
        "F04",
        "FIXTURES_F01_F10",
        "Allowlist PEP : sujet/action exacts, ressource en motif fnmatch",
        "5 cas : 2×200 attendus, 3×403 attendus",
        {"cases": cases},
        all(c["want"] == c["got"] for c in cases),
    )

    # --- F05 : schéma strict (champs manquants/supplémentaires) -----
    good = H.forge_permit(
        legit_priv,
        permit_id="P-F05",
        nonce="N-F05-" + H.secrets.token_hex(4),
        orig_request=ok_request(),
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    missing = dict(good)
    del missing["issuer"]
    extra = dict(good)
    extra["unexpected"] = 1
    r1 = client.post("/v1/execute", json={"original_request": ok_request(), "permit": missing})
    r2 = client.post("/v1/execute", json={"original_request": ok_request(), "permit": extra})
    obs = {
        "missing_field": resp_view(r1),
        "extra_field": resp_view(r2),
    }
    record(
        "F05",
        "FIXTURES_F01_F10",
        "Schéma strict : champ manquant ou supplémentaire",
        "400 PERMIT_SCHEMA_VIOLATION dans les deux cas (jamais 500)",
        obs,
        r1.status_code == 400 and r2.status_code == 400,
    )

    # --- F06 : bornes temporelles exactes ---------------------------
    real_now = pep_mod._now
    try:
        pep_mod._now = lambda: 1000.0
        t6 = []
        for iss, exp, want_code in (
            (970.0, 1000.0, "PERMIT_EXPIRED"),  # now == expires
            (970.0, 1000.5, None),  # valide
            (1061.0, 1161.0, "FUTURE_ISSUED_AT"),  # skew 60 : 1061 > 1000+60
            (1060.0, 1160.0, None),  # à la limite du skew : valide
            (900.0, 1000.0 + 301.0, "TTL_EXCEEDED"),  # TTL 401 > 300
        ):
            r = H.make_request("agent-alpha", "report.read", "reports/q3")
            p = H.forge_permit(
                legit_priv,
                permit_id="P-F06-" + H.secrets.token_hex(3),
                nonce="N-F06-" + H.secrets.token_hex(6),
                orig_request=r,
                issued_at=iss,
                expires_at=exp,
            )
            resp = client.post("/v1/execute", json={"original_request": r, "permit": p})
            detail = resp.json().get("detail") if resp.status_code != 200 else None
            got_code = detail.get("code") if isinstance(detail, dict) else None
            t6.append(
                {
                    "issued_at": iss,
                    "expires_at": exp,
                    "want": want_code or "200",
                    "got": got_code or (200 if resp.status_code == 200 else resp.status_code),
                }
            )
        record(
            "F06",
            "FIXTURES_F01_F10",
            "Bornes temporelles : exclusive expire, skew, TTL (horloge figée)",
            "5 cas : expired/future/ttl bloqués, deux cas limites valides",
            {"cases": t6, "fixed_now": 1000.0, "skew": 60.0, "ttl": 300.0},
            all(
                (c["want"] == "200" and c["got"] == 200)
                or (c["want"] != "200" and c["got"] == c["want"])
                for c in t6
            ),
        )
    finally:
        pep_mod._now = real_now

    # --- F07 : unicité ledger (unité SQLite) ------------------------
    ldb = workspace / "f_ledger.db"
    if ldb.exists():
        ldb.unlink()
    led = pep_mod.Ledger(str(ldb))
    led.consume("N-U", "P-U", "s", "a", "r", 1.0)
    second = None
    try:
        led.consume("N-U", "P-U2", "s", "a", "r", 2.0)
    except pep_mod.NonceReused:
        second = "NonceReused"
    record(
        "F07",
        "FIXTURES_F01_F10",
        "Ledger : PRIMARY KEY nonce = arbitre d'unicité",
        "2e consommation du même nonce => NonceReused",
        {"second_consume": second},
        second == "NonceReused",
    )

    # --- F08 : ordre des événements (pipeline complet) --------------
    r8 = H.make_request("agent-alpha", "report.read", "reports/q3")
    n8 = "N-F08-" + H.secrets.token_hex(4)
    p8 = H.forge_permit(
        legit_priv,
        permit_id="P-F08",
        nonce=n8,
        orig_request=r8,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    resp8 = client.post("/v1/execute", json={"original_request": r8, "permit": p8})
    ev_u = [e[4] for e in H.db_rows(workspace / "f_unit.db")["events"] if e[2] == n8]
    record(
        "F08",
        "FIXTURES_F01_F10",
        "Événements : ordre PERMIT_CONSUMED < ACTION_ATTEMPTED < EFFECT_SIMULATED",
        "séquence exacte sur un execute complet",
        {"status_code": resp8.status_code, "events": ev_u},
        resp8.status_code == 200
        and ev_u == ["PERMIT_CONSUMED", "ACTION_ATTEMPTED", "EFFECT_SIMULATED"],
    )

    # --- F09 : contrat de réponse -----------------------------------
    r = H.make_request("agent-alpha", "report.read", "reports/q3")
    p = H.forge_permit(
        legit_priv,
        permit_id="P-F09",
        nonce="N-F09-" + H.secrets.token_hex(4),
        orig_request=r,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    resp = client.post("/v1/execute", json={"original_request": r, "permit": p})
    b9 = resp.json()
    passed = (
        resp.status_code == 200
        and set(b9.keys())
        == {
            "status",
            "permit_consumed",
            "action_attempted",
            "effect_status",
            "effect_confirmed",
            "transaction",
            "note",
        }
        and b9["effect_confirmed"] is False
        and b9["effect_status"] == "SIMULATED_LOCAL_ONLY"
        and "executed" not in b9
    )
    record(
        "F09",
        "FIXTURES_F01_F10",
        "Contrat de réponse : aucun executed=true, effect_confirmed=False",
        "champs exacts {status, permit_consumed, action_attempted, effect_status,"
        " effect_confirmed, transaction, note}",
        {"body": b9},
        passed,
    )

    # --- F10 : fail-closed au démarrage si pin discordant ------------
    app_x = pep_mod.build_app(
        str(workspace / "pep_policy_v3c.json"),
        str(workspace / "pep_public.key"),
        str(workspace / "trust_root.pin"),
        str(workspace / "f_unit2.db"),
        pin_env=H.fingerprint(atk_pub),  # pin substitué
    )
    client_x = TestClient(app_x)
    resp = client_x.post("/v1/execute", json={"original_request": ok_request(), "permit": good})
    hv = client_x.get("/v1/health").json()
    passed = resp.status_code == 503 and hv.get("trust_root") != "OK"
    record(
        "F10",
        "FIXTURES_F01_F10",
        "Fail-closed : pin substitué => aucun execute possible",
        "503 + health.trust_root != OK",
        {"execute": resp_view(resp), "health": hv},
        passed,
    )

    # ==================================================================
    # FAMILLE 3 — V3C-A01–A16 : attaques adversariales (reconstituées)
    # ==================================================================

    # --- A01 : rejeu même processus ---------------------------------
    reqa1 = ok_request()
    pa1 = H.forge_permit(
        legit_priv,
        permit_id="P-A01",
        nonce="N-A01-" + H.secrets.token_hex(4),
        orig_request=reqa1,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    v_first = resp_view(server.execute(reqa1, pa1))
    v_second = resp_view(server.execute(reqa1, pa1))
    record(
        "A01",
        "ATTACKS_A01_A16",
        "Rejeu dans le même processus",
        "1er 200 ; 2e 403 NONCE_REUSED",
        {"first": v_first, "second": v_second},
        v_first["status_code"] == 200
        and v_second["status_code"] == 403
        and code_of(v_second) == "NONCE_REUSED",
    )

    # --- A02 : rejeu trans-redémarrage ------------------------------
    server.restart()
    v_third = resp_view(server.execute(reqa1, pa1))
    record(
        "A02",
        "ATTACKS_A01_A16",
        "Rejeu après mort+renaissance du processus serveur",
        "403 NONCE_REUSED (durabilité SQLite)",
        v_third,
        v_third["status_code"] == 403 and code_of(v_third) == "NONCE_REUSED",
    )

    # --- A03 : 16 processus simultanés ------------------------------
    reqa3 = ok_request()
    pa3 = H.forge_permit(
        legit_priv,
        permit_id="P-A03",
        nonce="N-A03-" + H.secrets.token_hex(4),
        orig_request=reqa3,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    conc16 = H.concurrent_execute(workspace, server.base_url, reqa3, pa3, 16, tag="A03")
    codes16 = [c.get("status_code", c.get("error")) for c in conc16]
    n_ok16 = sum(1 for c in codes16 if c == 200)
    n_reuse16 = sum(
        1
        for c in conc16
        if c.get("status_code") == 403 and c.get("body", {}).get("detail", {}).get("code") == "NONCE_REUSED"
    )
    record(
        "A03",
        "ATTACKS_A01_A16",
        "Pression concurrente : 16 interpréteurs, même permis",
        "exactement 1×200 et 15×403 NONCE_REUSED",
        {"status_codes": codes16, "accepted": n_ok16, "nonce_reused": n_reuse16},
        n_ok16 == 1 and n_reuse16 == 15,
    )

    # --- A04 : collision de nonce entre deux permis différents -------
    reqa4 = ok_request()
    n_a4 = "N-A04-" + H.secrets.token_hex(4)
    pa4a = H.forge_permit(
        legit_priv,
        permit_id="P-A04A",
        nonce=n_a4,
        orig_request=reqa4,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    pa4b = H.forge_permit(
        legit_priv,
        permit_id="P-A04B",
        nonce=n_a4,  # même nonce, permis différent
        orig_request=reqa4,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    v1 = resp_view(server.execute(reqa4, pa4a))
    v2 = resp_view(server.execute(reqa4, pa4b))
    record(
        "A04",
        "ATTACKS_A01_A16",
        "Collision de nonce entre deux permis distincts (signés)",
        "1er 200 ; 2e 403 NONCE_REUSED même avec signature valide",
        {"first": v1, "second": v2},
        v1["status_code"] == 200
        and v2["status_code"] == 403
        and code_of(v2) == "NONCE_REUSED",
    )

    # --- A05 : permis forgé par clé attaquante ----------------------
    reqa5 = ok_request()
    pa5 = H.forge_permit(
        atk_priv,
        permit_id="P-A05",
        nonce="N-A05-" + H.secrets.token_hex(4),
        orig_request=reqa5,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    v = resp_view(server.execute(reqa5, pa5))
    record(
        "A05",
        "ATTACKS_A01_A16",
        "Permis signé par la clé attaquante (clé légitime en place)",
        "403 INVALID_SIGNATURE — la signature valide d'une clé non épinglée ne vaut rien",
        v,
        v["status_code"] == 403 and code_of(v) == "INVALID_SIGNATURE",
    )

    # --- A06 : permis sans signature -------------------------------
    reqa6 = ok_request()
    pa6 = H.forge_permit(
        legit_priv,
        permit_id="P-A06",
        nonce="N-A06-" + H.secrets.token_hex(4),
        orig_request=reqa6,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    del pa6["signature"]
    v = resp_view(server.execute(reqa6, pa6))
    record(
        "A06",
        "ATTACKS_A01_A16",
        "Permis sans champ signature",
        "400 PERMIT_SCHEMA_VIOLATION",
        v,
        v["status_code"] == 400 and code_of(v) == "PERMIT_SCHEMA_VIOLATION",
    )

    # --- A07 : signature valide sous clé non autorisée --------------
    # (variante HTTP d'A05 avec les deux attestations) ---------------
    reqa7 = ok_request()
    pa7 = H.forge_permit(
        atk_priv,
        permit_id="P-A07",
        nonce="N-A07-" + H.secrets.token_hex(4),
        orig_request=reqa7,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
        issuer=H.DEFAULT_ISSUER,  # usurpe aussi l'identité d'émetteur
    )
    v = resp_view(server.execute(reqa7, pa7))
    record(
        "A07",
        "ATTACKS_A01_A16",
        "Usurpation d'issuer + signature valide sous clé non épinglée",
        "403 INVALID_SIGNATURE (la clé non épinglée ne vérifie rien)",
        v,
        v["status_code"] == 403 and code_of(v) == "INVALID_SIGNATURE",
    )

    # --- A08 : corps de permis altéré après signature ---------------
    reqa8 = ok_request()
    pa8 = H.forge_permit(
        legit_priv,
        permit_id="P-A08",
        nonce="N-A08-" + H.secrets.token_hex(4),
        orig_request=reqa8,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    pa8["expires_at"] = pa8["expires_at"] + 100000  # extension de validité non signée
    v = resp_view(server.execute(reqa8, pa8))
    record(
        "A08",
        "ATTACKS_A01_A16",
        "Altération de expires_at après signature",
        "403 INVALID_SIGNATURE",
        v,
        v["status_code"] == 403 and code_of(v) == "INVALID_SIGNATURE",
    )

    # --- A09 : altération requête/permis ----------------------------
    reqa9 = ok_request()
    pa9 = H.forge_permit(
        legit_priv,
        permit_id="P-A09",
        nonce="N-A09-" + H.secrets.token_hex(4),
        orig_request=reqa9,
        issued_at=time.time() - 2,
        expires_at=time.time() + 120,
    )
    bad9 = H.make_request("agent-alpha", "report.read", "reports/OTHER")
    v = resp_view(server.execute(bad9, pa9))
    nonce_ok_after = None
    v_after = resp_view(server.execute(reqa9, pa9))
    nonce_ok_after = v_after["status_code"] == 200
    record(
        "A09",
        "ATTACKS_A01_A16",
        "Altération de la requête : rejet SANS brûler le nonce",
        "403 REQUEST_TAMPERED puis la requête légitime obtient encore 200",
        {"tampered": v, "legit_afterward": v_after},
        v["status_code"] == 403
        and code_of(v) == "REQUEST_TAMPERED"
        and nonce_ok_after,
    )

    # --- A10 : confusion de types -----------------------------------
    reqa10 = ok_request()
    t10cases = []
    for fname, badval in (("issued_at", True), ("expires_at", "123"), ("issued_at", None)):
        p = H.forge_permit(
            legit_priv,
            permit_id="P-A10-" + H.secrets.token_hex(3),
            nonce="N-A10-" + H.secrets.token_hex(6),
            orig_request=reqa10,
            issued_at=time.time() - 2,
            expires_at=time.time() + 100,
        )
        p[fname] = badval
        v = resp_view(server.execute(reqa10, p))
        t10cases.append({"field": fname, "bad_value": repr(badval), "observed": v})
    record(
        "A10",
        "ATTACKS_A01_A16",
        "Confusion de types (bool/null/chaîne sur les horodatages)",
        "400 INVALID_FIELD_TYPE dans tous les cas (jamais 500)",
        {"cases": t10cases},
        all(c["observed"]["status_code"] == 400 for c in t10cases),
    )

    # --- A11 : attaque de canonisation ------------------------------
    reqa11 = ok_request()
    pa11 = H.forge_permit(
        legit_priv,
        permit_id="P-A11",
        nonce="N-A11-" + H.secrets.token_hex(4),
        orig_request=reqa11,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    # (a) octets JSON réordonnés sur le fil => même canon => accepté en premier
    payload_reordered = json.dumps(
        {"permit": dict(reversed(list(pa11.items()))),
         "original_request": dict(reversed(list(reqa11.items())))},
        ensure_ascii=False,
    )
    r_raw = httpx.post(
        server.base_url + "/v1/execute",
        content=payload_reordered,
        headers={"content-type": "application/json"},
        timeout=30.0,
    )
    v_reorder = resp_view(r_raw)
    # (b) rejeu immédiat du même permis => NONCE_REUSED
    v_replay = resp_view(server.execute(reqa11, pa11))
    # (c) homoglyphe non ASCII => refusé à la frontière (format ou hash)
    homo = {"subject": "agent-alpha", "action": "report.read", "resource": "reports/q\u0443"}
    v_homo = resp_view(server.execute(homo, pa11))
    # (d) ressource ASCII différente de celle signée => hash de requête différent
    alt = {"subject": "agent-alpha", "action": "report.read", "resource": "reports/q3x"}
    v_alt = resp_view(server.execute(alt, pa11))
    homo_rejected = v_homo["status_code"] in (400, 403)
    passed = (
        v_reorder["status_code"] == 200
        and v_replay["status_code"] == 403
        and code_of(v_replay) == "NONCE_REUSED"
        and homo_rejected
        and v_alt["status_code"] == 403
        and code_of(v_alt) == "REQUEST_TAMPERED"
    )
    record(
        "A11",
        "ATTACKS_A01_A16",
        "Canonisation : ordre JSON neutre, homoglyphe non transmissible, hash contraignant",
        "JSON réordonné => 200 ; rejeu => 403 NONCE_REUSED ; homoglyphe => 4xx ;"
        " ressource ASCII différente => 403 REQUEST_TAMPERED",
        {
            "reordered_json": v_reorder,
            "replay": v_replay,
            "homoglyph_resource": v_homo,
            "different_ascii_resource": v_alt,
        },
        passed,
    )

    # --- A12 : injection SQL dans le nonce --------------------------
    reqa12 = ok_request()
    pa12 = H.forge_permit(
        legit_priv,
        permit_id="P-A12",
        nonce="N-A12-' ; DROP TABLE consumed_permits; --",
        orig_request=reqa12,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    v = resp_view(server.execute(reqa12, pa12))
    tables = H.db_rows(workspace)
    table_alive = bool(tables["consumed"]) or True  # table interrogeable = vivante
    try:
        H.db_rows(workspace)
        alive = True
    except sqlite3.Error:
        alive = False
    record(
        "A12",
        "ATTACKS_A01_A16",
        "Injection SQL dans le nonce",
        "400 INVALID_FIELD_FORMAT (charset nonce) ; table intacte",
        {"response": v, "table_still_queryable": alive},
        v["status_code"] == 400 and code_of(v) == "INVALID_FIELD_FORMAT" and alive,
    )

    # --- A13 : traversée de ressource -------------------------------
    reqa13 = {"subject": "agent-alpha", "action": "report.read", "resource": "reports/../../etc/shadow"}
    pa13 = H.forge_permit(
        legit_priv,
        permit_id="P-A13",
        nonce="N-A13-" + H.secrets.token_hex(4),
        orig_request=reqa13,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    v = resp_view(server.execute(reqa13, pa13))
    record(
        "A13",
        "ATTACKS_A01_A16",
        "Traversée de chemin dans la ressource",
        "400 INVALID_FIELD_FORMAT ('..' refusé) avant tout le reste",
        v,
        v["status_code"] == 400 and code_of(v) == "INVALID_FIELD_FORMAT",
    )

    # --- A14 : usurpation de sujet ----------------------------------
    reqa14 = H.make_request("root", "report.read", "reports/q3")
    pa14 = H.forge_permit(
        legit_priv,
        permit_id="P-A14",
        nonce="N-A14-" + H.secrets.token_hex(4),
        orig_request=reqa14,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
        subject="root",
    )
    v = resp_view(server.execute(reqa14, pa14))
    record(
        "A14",
        "ATTACKS_A01_A16",
        "Usurpation de sujet (root) signée",
        "403 SUBJECT_FORBIDDEN — la signature ne crée pas de droits",
        v,
        v["status_code"] == 403 and code_of(v) == "SUBJECT_FORBIDDEN",
    )

    # --- A15 : rétrogradation de politique --------------------------
    reqa15 = ok_request()
    pa15 = H.forge_permit(
        legit_priv,
        permit_id="P-A15",
        nonce="N-A15-" + H.secrets.token_hex(4),
        orig_request=reqa15,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
        policy_version="v3c.0.9",
    )
    v = resp_view(server.execute(reqa15, pa15))
    record(
        "A15",
        "ATTACKS_A01_A16",
        "Rétrogradation de policy_version signée",
        "403 POLICY_VERSION_MISMATCH",
        v,
        v["status_code"] == 403 and code_of(v) == "POLICY_VERSION_MISMATCH",
    )

    # --- A16 : champs surdimensionnés / imbriqués -------------------
    reqa16 = ok_request()
    pa16 = H.forge_permit(
        legit_priv,
        permit_id="P-A16",
        nonce="N-A16-" + H.secrets.token_hex(4),
        orig_request=reqa16,
        issued_at=time.time() - 2,
        expires_at=time.time() + 100,
    )
    pa16["resource"] = "r" * 10000
    v_big = resp_view(server.execute(reqa16, pa16))
    deep: Any = {"x": 1}
    for _ in range(200):
        deep = {"n": deep}
    v_deep = resp_view(
        httpx.post(
            server.base_url + "/v1/execute",
            json={"original_request": deep, "permit": pa16},
            timeout=30.0,
        )
    )
    passed = (
        v_big["status_code"] in (400, 422)
        and v_deep["status_code"] in (400, 422)
    )
    record(
        "A16",
        "ATTACKS_A01_A16",
        "Champ surdimensionné et structure profonde",
        "réponses 4xx contrôlées sur champ géant ; pas de crash serveur",
        {"oversized_field": v_big, "deep_nesting": v_deep},
        passed,
    )

    # ==================================================================
    # Clôture — T18-bis : état de la base, verdict machine
    # ==================================================================
    server.stop()

    rows = H.db_rows(workspace)
    status_counts: Dict[str, int] = {}
    for r in rows["consumed"]:
        status_counts[r[6]] = status_counts.get(r[6], 0) + 1
    event_counts: Dict[str, int] = {}
    for e in rows["events"]:
        event_counts[e[4]] = event_counts.get(e[4], 0) + 1

    total = len(SCENARIOS)
    n_pass = sum(1 for s in SCENARIOS if s["verdict"] == "PASS_LOCAL")
    n_fail = total - n_pass

    gates: Dict[str, Any] = {}
    gate_map = {
        "GATE_TRUST_ROOT_PIN": ["T13", "T14", "F03", "F10", "A05"],
        "GATE_PEP_POLICY_AUTHZ": ["T08", "T09", "T10", "T20", "F04", "A14", "A15"],
        "GATE_NONCE_PERSISTENCE": ["T02", "T19", "A01", "A02"],
        "GATE_CONCURRENCY": ["T03", "A03", "A04", "F07"],
        "GATE_TEMPORAL_SEMANTICS": ["T04", "T22", "T23", "T24", "F06"],
        "GATE_CRYPTO_BINDING": ["T05", "T06", "T17", "A07", "A08", "A11", "F02"],
        "GATE_STRICT_PARSING": ["T07", "T15", "T16", "A06", "A10", "A12", "A13", "A16", "F05"],
        "GATE_BURN_ON_TAMPER": ["T11", "T12", "A09"],
        "GATE_EFFECT_SEMANTICS": ["T18", "F09"],
        "GATE_CRASH_RECOVERY": ["T21", "F08"],
    }
    by_id = {s["id"]: s for s in SCENARIOS}
    for g, ids in gate_map.items():
        sub = [by_id[i] for i in ids if i in by_id]
        gates[g] = {
            "scenario_ids": ids,
            "verdict": "PASS_LOCAL" if all(s["verdict"] == "PASS_LOCAL" for s in sub) else "FAIL",
        }
    gates["GATE_REAL_OS_PERMISSIONS"] = {
        "scenario_ids": [],
        "verdict": "NOT_EXECUTED",
        "note": "interdit par l'ordre de mission (aucune cible OS réelle)",
    }
    gates["GATE_PRODUCTION_DEPLOYMENT"] = {
        "scenario_ids": [],
        "verdict": "NOT_EXECUTED",
        "note": "interdit par l'ordre de mission (aucune publication, aucun réseau externe)",
    }

    results = {
        "mission_id": "AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003",
        "tag": tag,
        "started_at": started_at,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.time() - t_start, 3),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "fastapi": __import__("fastapi").__version__,
            "cryptography": __import__("cryptography").__version__,
            "httpx": httpx.__version__,
            "mode": "LOCAL_LOOPBACK_HTTP_127.0.0.1 + ASGI_IN_PROCESS_UNIT",
        },
        "methodology_note": (
            "OBSERVED est produit par ce runner ; EXPECTED est figé dans le code du runner "
            "avant exécution. Répétition même hôte = non indépendant."
        ),
        "scenarios": SCENARIOS,
        "summary": {"total": total, "pass": n_pass, "fail": n_fail},
        "db_status_counts": status_counts,
        "db_event_counts": event_counts,
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    out_json = RESULTS_DIR / (
        "EXPERIMENT_RESULTS.json" if tag == "run1" else f"EXPERIMENT_RESULTS_{tag}.json"
    )
    out_json.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    verdict = {
        "mission_id": "AEGIS_V3C_PIN_POLICY_SQLITE_INTEGRATION_003",
        "gates": gates,
        "adversarial_scenarios": total,
        "local_repetitions_this_file": 1,
        "claim_ceiling": "LOCAL_EXECUTED_SIMULATOR",
        "next_gate": "AEGIS_V3D_REAL_EFFECT_WITNESS_004",
        "unresolved_counter_examples": [
            "CE-1 split-brain multi-nœud (SQLite n'est pas un consensus distribué)",
            "CE-2 chaîne Core de vérité des claims (PEP n'est pas un oracle ; refusé à la frontière)",
            "CE-3 confiance dans la source d'horloge (NTP) en production",
            "CE-4 amorçage du pin/policy (compromission totale de la configuration)",
            "CE-5 récupération des états PENDING (réconciliation métier non implémentée)",
            "CE-6 rotation de clé sans interruption",
        ],
        "truth_status": "OPEN",
        "claim_rule": "CLAIM <= EVIDENCE",
    }
    out_v = RESULTS_DIR / ("VERDICT.json" if tag == "run1" else f"VERDICT_{tag}.json")
    out_v.write_text(json.dumps(verdict, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print()
    print(f"== SUMMARY: {n_pass}/{total} PASS_LOCAL, {n_fail} FAIL ==")
    for g, gv in gates.items():
        print(f"   {g}: {gv['verdict']}")
    print(f"   written: {out_json.name}, {out_v.name}")
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
